"""Named connection profiles, without passwords."""

import json
import uuid

from ad_settings import CONFIG_DIRECTORY, write_settings


PROFILES_PATH = CONFIG_DIRECTORY / "connections.json"
LEGACY_PATH = CONFIG_DIRECTORY / "connection.json"
CREDENTIAL_SERVICE = "ad-directory"


def validate_bind_user(user):
    if not isinstance(user, str) or not user.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in user
    ):
        raise RuntimeError("Bind user must be a nonempty DOMAIN\\account or UPN without control characters.")
    return user.strip()


def validate_server(server):
    if (
        not isinstance(server, str) or not server.strip()
        or any(character.isspace() or ord(character) < 32 for character in server)
        or any(character in server for character in "/\\:")
    ):
        raise RuntimeError("LDAP server must be a hostname or IPv4 address, without a URL or port.")
    return server


def validate_profile_name(name):
    if not isinstance(name, str) or not name.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in name
    ):
        raise RuntimeError("Connection name must be nonempty and contain no control characters.")
    return name.strip()


def new_credential_key():
    return "profile:" + uuid.uuid4().hex


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as error:
        raise RuntimeError(f"Could not read connection settings {path}: {error}") from error


def load_profiles(path=PROFILES_PATH, legacy_path=LEGACY_PATH):
    data = read_json(path)
    if data is None:
        legacy = read_json(legacy_path)
        if legacy is None:
            return {}, None
        if not isinstance(legacy, dict):
            raise RuntimeError("Invalid legacy connection settings: expected an object.")
        if not legacy.get("server") or not legacy.get("bind_user"):
            return {}, None
        user = validate_bind_user(legacy["bind_user"])
        server = validate_server(legacy["server"])
        verified = legacy.get("tls_verified", True)
        if not isinstance(verified, bool):
            raise RuntimeError("Invalid connection settings: tls_verified must be true or false.")
        return {"Imported connection": {
            "server": server, "bind_user": user, "tls_verified": verified,
            "credential_key": new_credential_key(), "legacy_credential_key": user,
            "password_stored": False,
        }}, "Imported connection"
    if not isinstance(data, dict) or not isinstance(data.get("profiles"), dict):
        raise RuntimeError(f"Invalid connection profiles {path}: expected a profiles object.")
    profiles = data["profiles"]
    seen = set()
    for name, profile in profiles.items():
        if validate_profile_name(name) != name or name.casefold() in seen:
            raise RuntimeError(f"Invalid or duplicate connection name in {path}.")
        seen.add(name.casefold())
        if not isinstance(profile, dict):
            raise RuntimeError(f"Invalid connection profile {name!r}.")
        validate_server(profile.get("server"))
        validate_bind_user(profile.get("bind_user"))
        if (
            not isinstance(profile.get("tls_verified"), bool)
            or not isinstance(profile.get("password_stored"), bool)
            or not isinstance(profile.get("credential_key"), str)
            or not profile["credential_key"]
            or ("legacy_credential_key" in profile and (
                not isinstance(profile["legacy_credential_key"], str) or not profile["legacy_credential_key"]
            ))
        ):
            raise RuntimeError(f"Invalid connection profile {name!r}.")
    selected = data.get("selected")
    if selected is not None and selected not in profiles:
        raise RuntimeError(f"Invalid selected connection in {path}.")
    return profiles, selected


def save_profiles(profiles, selected, path=PROFILES_PATH):
    write_settings(path, {"profiles": profiles, "selected": selected})
