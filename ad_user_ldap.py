#!/usr/bin/env python3
"""Browse AD users, groups, and computers over LDAPS."""

import argparse
import base64
import getpass
import json
import os
import ssl
import stat
import sys
from collections.abc import Mapping
from datetime import date, datetime
from pathlib import Path

from ldap3 import (
    NONE,
    Connection,
    Server,
    Tls,
)
from ldap3.core.exceptions import LDAPException
from ad_connections import CREDENTIAL_SERVICE, load_profiles, save_profiles, validate_bind_user, validate_server
from ad_directory import ADDirectory
from ad_settings import CONFIG_DIRECTORY, write_settings


CONNECTION_SETTINGS_PATH = CONFIG_DIRECTORY / "connection.json"


def resolve_connection_settings(user, server, require_server=True, tls_verified=None):
    try:
        settings = json.loads(CONNECTION_SETTINGS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        settings = {}
    except (OSError, ValueError) as error:
        raise RuntimeError(f"Could not read connection settings: {error}") from error
    if not isinstance(settings, dict):
        raise RuntimeError("Invalid connection settings: expected an object.")
    if user is None:
        user = settings.get("bind_user")
    if user is None:
        raise RuntimeError("No bind user configured. Supply --bind-user 'DOMAIN\\account' or a UPN.")
    user = validate_bind_user(user)
    previous_server = settings.get("server")
    if server is None:
        server = settings.get("server")
    if server is not None:
        validate_server(server)
    elif require_server:
        raise RuntimeError("No LDAP server configured. Supply --server dc.example.com.")
    if tls_verified is not None and server is None:
        raise RuntimeError("Configure --server before setting TLS verification.")
    if tls_verified is None:
        if server is not None and (
            not isinstance(previous_server, str) or server.casefold() != previous_server.casefold()
        ):
            tls_verified = True
        else:
            tls_verified = settings.get("tls_verified", True)
    if not isinstance(tls_verified, bool):
        raise RuntimeError("Invalid connection settings: tls_verified must be true or false.")
    updated = {**settings, "bind_user": user}
    if server is not None:
        updated["server"] = server
        updated["tls_verified"] = tls_verified
    if updated != settings:
        write_settings(CONNECTION_SETTINGS_PATH, updated)
    return user, server, tls_verified


def native_credential_store():
    label = {"darwin": "macOS Keychain", "win32": "Windows Credential Manager"}.get(sys.platform)
    if label is None:
        raise RuntimeError("Native credential storage requires macOS or Windows. Use a password prompt or --password-file.")
    try:
        from keyring.errors import KeyringError

        if sys.platform == "darwin":
            from keyring.backends.macOS import Keyring

            return Keyring(), label, (KeyringError, OSError)
        from keyring.backends.Windows import WinVaultKeyring, pywintypes

        backend = WinVaultKeyring()
        if backend.priority <= 0:
            raise RuntimeError("Windows Credential Manager backend is unavailable.")
        return backend, label, (KeyringError, OSError, pywintypes.error)
    except ImportError as error:
        raise RuntimeError(f"Could not load {label}. Install requirements.txt: {error}") from error


def stored_password(user, credential_key=None):
    backend, label, errors = native_credential_store()
    try:
        password = backend.get_password(CREDENTIAL_SERVICE, credential_key or user)
    except errors as error:
        raise RuntimeError(f"Could not read {label}: {error}") from error
    if not password:
        raise RuntimeError(f"No password stored for {user!r} in {label}. Save a password first.")
    return password


def store_password(user, password, credential_key=None):
    backend, label, errors = native_credential_store()
    try:
        backend.set_password(CREDENTIAL_SERVICE, credential_key or user, password)
    except errors as error:
        raise RuntimeError(f"Could not save to {label}: {error}") from error
    return label


def forget_password(credential_key):
    backend, label, errors = native_credential_store()
    try:
        backend.delete_password(CREDENTIAL_SERVICE, credential_key)
    except errors as error:
        raise RuntimeError(f"Could not delete password from {label}: {error}") from error


def save_stored_password(user):
    return store_password(user, bind_password(None, user))


def open_directory(user, server, verified, password, target):
    connection = None
    try:
        tls = Tls(validate=ssl.CERT_REQUIRED if verified else ssl.CERT_NONE)
        ldap_server = Server(server, port=636, use_ssl=True, tls=tls, get_info=NONE, connect_timeout=15)
        connection = Connection(
            ldap_server, user=user, password=password, raise_exceptions=True, check_names=False,
            auto_referrals=False, auto_range=True, receive_timeout=30,
        )
        if not connection.bind():
            raise RuntimeError(f"LDAP bind failed: {connection.result}")
        directory = ADDirectory(connection)
        record = directory.lookup(target) if target else directory.read(directory.base_dn)
        return connection, directory, record
    except (LDAPException, OSError, RuntimeError, ValueError):
        if connection is not None and connection.bound:
            connection.unbind()
        raise


def connection_dialog(target=None):
    from ad_connection_tui import ConnectionApp

    return ConnectionApp(
        lambda profile, password: open_directory(
            profile["bind_user"], profile["server"], profile["tls_verified"], password, target
        ),
        stored_password, store_password, forget_password,
    ).run()


def json_value(value):
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, bytes):
        return {"encoding": "base64", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"Cannot serialize LDAP value of type {type(value).__name__}")


def bind_password(password_file, user):
    if password_file is None:
        password = getpass.getpass(f"LDAP password for {user}: ")
    else:
        with password_file.open(encoding="utf-8") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError("The password file must be a regular file.")
            if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
                raise RuntimeError(f"Password file permissions are too open; run chmod 600 {password_file}")
            password = handle.read().rstrip("\r\n")
        if "\n" in password or "\r" in password:
            raise RuntimeError("The password file must contain a single line.")
    if not password:
        raise RuntimeError("The bind password must not be empty.")
    return password


def lookup_user(connection, user):
    return ADDirectory(connection).lookup(user)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--server",
        help="Legacy LDAPS server setting (port 636); bypasses the connection dialog.",
    )
    parser.add_argument(
        "--bind-user",
        help="Legacy bind identity (DOMAIN\\account or UPN); bypasses the connection dialog.",
    )
    parser.add_argument("--connection", help="Use a named connection profile instead of the startup dialog.")
    tls_options = parser.add_mutually_exclusive_group()
    tls_options.add_argument(
        "--tls-verified", dest="tls_verified", action="store_true", default=None,
        help="Verify the LDAPS server certificate and hostname (default); save this choice.",
    )
    tls_options.add_argument(
        "--tls-unverified", dest="tls_verified", action="store_false",
        help="Disable certificate and hostname verification for this server; save this unsafe choice.",
    )
    parser.add_argument("user", nargs="?", help="User account, UPN or full name, group name, or computer name/DNS name; omit to browse the domain")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON instead of opening the read-only terminal UI",
    )
    password_options = parser.add_mutually_exclusive_group()
    password_options.add_argument(
        "--password-file",
        type=Path,
        help="Read the bind password from a private single-line file instead of prompting",
    )
    password_options.add_argument(
        "--use-stored-credentials", "--use-keychain",
        dest="use_stored_credentials",
        action="store_true",
        help="Read the selected bind user's password from macOS Keychain or Windows Credential Manager",
    )
    password_options.add_argument(
        "--save-credentials", "--save-keychain-password",
        dest="save_credentials",
        action="store_true",
        help="Prompt for a password and save it in the native OS credential store without connecting to LDAP",
    )
    args = parser.parse_args()
    interactive = not args.json and sys.stdin.isatty() and sys.stdout.isatty()
    if not args.save_credentials and not args.user and not interactive:
        parser.error("a user, group, or computer is required for JSON output")
    if args.save_credentials and args.user:
        parser.error("--save-credentials does not take a lookup target")
    if args.connection and any((args.server is not None, args.bind_user is not None, args.tls_verified is not None)):
        parser.error("--connection cannot be combined with --server, --bind-user, or TLS flags")

    connection = None
    directory = None
    try:
        explicit_connection = any((
            args.bind_user is not None, args.server is not None, args.tls_verified is not None,
            args.password_file is not None, args.use_stored_credentials, args.save_credentials,
            args.connection is not None,
        ))
        if interactive and not explicit_connection:
            selected = connection_dialog(args.user)
            if selected is None:
                return 0
            connection, directory, result, tls_verified = selected
        else:
            credential_key = None
            if args.connection:
                profiles, selected_profile = load_profiles()
                if args.connection not in profiles:
                    raise RuntimeError(f"No connection profile named {args.connection!r}.")
                profile = profiles[args.connection]
                bind_user, ldap_server, tls_verified = (
                    profile["bind_user"], profile["server"], profile["tls_verified"]
                )
                credential_key = profile["credential_key"]
            else:
                bind_user, ldap_server, tls_verified = resolve_connection_settings(
                    args.bind_user, args.server, require_server=not args.save_credentials,
                    tls_verified=args.tls_verified,
                )
            if args.save_credentials:
                label = (
                    store_password(bind_user, bind_password(None, bind_user), credential_key)
                    if credential_key else save_stored_password(bind_user)
                )
                if args.connection:
                    profiles[args.connection] = {
                        key: value for key, value in profile.items() if key != "legacy_credential_key"
                    }
                    profiles[args.connection]["password_stored"] = True
                    save_profiles(profiles, selected_profile)
                print(f"Saved password for {bind_user} in {label} (service: {CREDENTIAL_SERVICE}).")
                return 0
            if args.use_stored_credentials:
                legacy_key = profile.get("legacy_credential_key") if args.connection else None
                password = stored_password(bind_user, legacy_key or credential_key)
                if legacy_key:
                    store_password(bind_user, password, credential_key)
                    profiles[args.connection] = {
                        key: value for key, value in profile.items() if key != "legacy_credential_key"
                    }
                    profiles[args.connection]["password_stored"] = True
                    save_profiles(profiles, selected_profile)
            else:
                password = bind_password(args.password_file, bind_user)
            if not tls_verified:
                print("Warning: TLS certificate and hostname verification are disabled.", file=sys.stderr)
            connection, directory, result = open_directory(
                bind_user, ldap_server, tls_verified, password, args.user,
            )
        if not interactive:
            print(json.dumps(result, indent=2, ensure_ascii=False, default=json_value))
        else:
            from ad_user_tui import ADUserApp

            history = None
            while True:
                app = ADUserApp(result, json_value, directory, tls_verified=tls_verified)
                if history is not None:
                    app.history, app.history_index = history
                if app.run() != "connections":
                    break
                result = app.record
                history = (app.history[:], app.history_index)
                selected = connection_dialog()
                if selected is None:
                    continue
                new_connection, new_directory, new_result, new_tls_verified = selected
                try:
                    directory.close()
                except (LDAPException, OSError, RuntimeError):
                    new_directory.close()
                    raise
                connection, directory, result, tls_verified = (
                    new_connection, new_directory, new_result, new_tls_verified
                )
                history = None
        return 0
    except (LDAPException, OSError, RuntimeError, ValueError, EOFError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    finally:
        if connection is not None and connection.bound:
            if directory is not None:
                directory.close()
            else:
                connection.unbind()


if __name__ == "__main__":
    sys.exit(main())
