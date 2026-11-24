import asyncio
import html
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from textual.widgets import Checkbox, Input, Select, Static

import ad_user_ldap as cli
from ad_connection_tui import ConnectionApp
from ad_connections import load_profiles


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "connections.json"
        self.legacy = Path(self.temporary.name) / "connection.json"

    def test_imports_legacy_settings_without_writing_or_reading_passwords(self):
        self.legacy.write_text(json.dumps({
            "server": "dc.example.com", "bind_user": "user", "tls_verified": False,
        }))
        profiles, selected = load_profiles(self.path, self.legacy)
        self.assertEqual(selected, "Imported connection")
        self.assertFalse(profiles[selected]["tls_verified"])
        self.assertTrue(profiles[selected]["credential_key"].startswith("profile:"))
        self.assertEqual(profiles[selected]["legacy_credential_key"], "user")
        self.assertFalse(self.path.exists())

    def test_invalid_profiles_are_rejected(self):
        self.path.write_text('{"profiles":{"bad":{"server":"dc.example.com"}}}')
        with self.assertRaises(RuntimeError):
            load_profiles(self.path, self.legacy)

    def test_existing_profiles_default_to_ldaps_and_invalid_transport_is_rejected(self):
        profile = {"server": "dc.example.com", "bind_user": "user", "tls_verified": True,
                   "credential_key": "profile:example", "password_stored": False}
        self.path.write_text(json.dumps({"profiles": {"Example": profile}, "selected": "Example"}))
        loaded, _ = load_profiles(self.path, self.legacy)
        self.assertTrue(loaded["Example"].get("use_ssl", True))
        profile["use_ssl"] = "false"
        self.path.write_text(json.dumps({"profiles": {"Example": profile}, "selected": "Example"}))
        with self.assertRaisesRegex(RuntimeError, "Invalid connection profile"):
            load_profiles(self.path, self.legacy)

    def test_profile_cli_uses_its_own_credential_key(self):
        profile = {"server": "dc.example.com", "bind_user": "user", "tls_verified": True,
                   "credential_key": "profile:example", "password_stored": True}
        connection = Mock(bound=True)
        directory = Mock()
        with patch("sys.argv", ["ad_user_ldap.py", "target", "--json", "--connection", "Example",
                                "--use-stored-credentials"]), \
             patch.object(cli, "load_profiles", return_value=({"Example": profile}, "Example")), \
             patch.object(cli, "stored_password", return_value="not-a-real-password") as get_password, \
             patch.object(cli, "open_directory", return_value=(connection, directory, {"dn": "test"})), \
             patch("sys.stdout"):
            self.assertEqual(cli.main(), 0)
        get_password.assert_called_once_with("user", "profile:example")

    def test_profile_cli_migrates_legacy_password_to_profile_key(self):
        profile = {"server": "dc.example.com", "bind_user": "user", "tls_verified": True,
                   "credential_key": "profile:example", "legacy_credential_key": "user",
                   "password_stored": False}
        connection, directory = Mock(bound=True), Mock()
        with patch("sys.argv", ["ad_user_ldap.py", "target", "--json", "--connection", "Imported connection",
                                "--use-stored-credentials"]), \
             patch.object(cli, "load_profiles", return_value=({"Imported connection": profile}, "Imported connection")), \
             patch.object(cli, "stored_password", return_value="not-a-real-password") as get_password, \
             patch.object(cli, "store_password") as put_password, \
             patch.object(cli, "save_profiles") as save_profiles, \
             patch.object(cli, "open_directory", return_value=(connection, directory, {"dn": "test"})), \
             patch("sys.stdout"):
            self.assertEqual(cli.main(), 0)
        get_password.assert_called_once_with("user", "user")
        put_password.assert_called_once_with("user", "not-a-real-password", "profile:example")
        saved = save_profiles.call_args.args[0]["Imported connection"]
        self.assertNotIn("legacy_credential_key", saved)
        self.assertTrue(saved["password_stored"])

    def test_named_unencrypted_profile_warns_and_uses_plaintext(self):
        profile = {"server": "dc.example.com", "bind_user": "user", "tls_verified": True,
                   "use_ssl": False, "credential_key": "profile:example", "password_stored": True}
        connection, directory = Mock(bound=True), Mock()
        with patch("sys.argv", ["ad_user_ldap.py", "target", "--json", "--connection", "Plain",
                                "--use-stored-credentials"]), \
             patch.object(cli, "load_profiles", return_value=({"Plain": profile}, "Plain")), \
             patch.object(cli, "stored_password", return_value="not-a-real-password"), \
             patch.object(cli, "open_directory", return_value=(connection, directory, {"dn": "test"})) as opened, \
             patch("sys.stdout"), patch("sys.stderr") as stderr:
            self.assertEqual(cli.main(), 0)
        self.assertFalse(opened.call_args.kwargs["use_ssl"])
        self.assertIn("unencrypted", "".join(call.args[0] for call in stderr.write.call_args_list))

    def test_browser_connection_shortcut_switches_or_resumes(self):
        old_connection = Mock(bound=True)
        new_connection = Mock(bound=True)
        old_directory, new_directory = Mock(), Mock()
        old_record, current_record, new_record = ({"dn": value} for value in ("old", "current", "new"))
        first, resumed, switched = Mock(), Mock(), Mock()
        first.run.return_value = resumed.run.return_value = "connections"
        switched.run.return_value = None
        first.record, first.history, first.history_index = current_record, ["old", "current"], 1
        resumed.record = current_record
        with patch("sys.argv", ["ad_user_ldap.py"]), patch("sys.stdin") as stdin, \
             patch("sys.stdout") as stdout, \
             patch.object(cli, "connection_dialog", side_effect=[
                 (old_connection, old_directory, old_record, True, True), None,
                 (new_connection, new_directory, new_record, False, False),
             ]) as dialog, \
             patch("ad_user_tui.ADUserApp", side_effect=[first, resumed, switched]) as browser:
            stdin.isatty.return_value = stdout.isatty.return_value = True
            self.assertEqual(cli.main(), 0)
        self.assertEqual(dialog.call_args_list, [call(None), call(), call()])
        self.assertEqual((resumed.history, resumed.history_index), (["old", "current"], 1))
        self.assertEqual(browser.call_args_list[1].args[0], current_record)
        self.assertEqual(browser.call_args_list[2].args[0], new_record)
        self.assertFalse(browser.call_args_list[2].kwargs["tls_verified"])
        self.assertFalse(browser.call_args_list[2].kwargs["use_ssl"])
        old_directory.close.assert_called_once()
        new_directory.close.assert_called_once()


class ConnectionDialogTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "connections.json"
        self.legacy = Path(self.temporary.name) / "connection.json"
        self.saved = {}

        def put(user, password, key):
            self.saved[key] = password

        def get(user, key):
            if key not in self.saved:
                raise RuntimeError("No stored password")
            return self.saved[key]

        self.connect = Mock(return_value=("connection", "directory", {"dn": "test"}))
        self.app = ConnectionApp(self.connect, get, put, self.saved.pop,
                                 profiles_path=self.path, legacy_path=self.legacy)

    async def fill(self, pilot, name, server, user, password):
        self.app.query_one("#name", Input).value = name
        self.app.query_one("#server", Input).value = server
        self.app.query_one("#bind-user", Input).value = user
        self.app.query_one("#password", Input).value = password
        await pilot.pause()

    async def test_save_multiple_profiles_without_writing_passwords(self):
        async with self.app.run_test(size=(100, 40)) as pilot:
            await self.fill(pilot, "First", "first.example.com", "user", "first-secret")
            self.app.query_one("#remember", Checkbox).value = True
            self.app.query_one("#save").press()
            await pilot.pause()
            first = self.app.profiles["First"]
            self.assertEqual(self.saved[first["credential_key"]], "first-secret")
            self.app.query_one("#profiles", Select).value = ""
            await pilot.pause()
            await self.fill(pilot, "Second", "second.example.com", "user", "second-secret")
            self.app.query_one("#remember", Checkbox).value = True
            self.app.query_one("#save").press()
            await pilot.pause()
            second = self.app.profiles["Second"]
            self.assertNotEqual(first["credential_key"], second["credential_key"])
            self.assertEqual(self.saved[second["credential_key"]], "second-secret")
            text = self.path.read_text()
            self.assertNotIn("first-secret", text)
            self.assertNotIn("second-secret", text)
            self.app.query_one("#profiles", Select).value = "First"
            await pilot.pause()
            self.assertEqual(self.app.query_one("#server", Input).value, "first.example.com")
            self.assertEqual(self.app.query_one("#password", Input).value, "")
            self.assertIn("Leave blank to use the saved password", str(self.app.query_one("#password-hint", Static).render()))
            self.assertIn("service=ad-directory, account=" + first["credential_key"],
                          str(self.app.query_one("#credential-info", Static).render()))

    async def test_saved_password_is_used_when_field_is_blank(self):
        async with self.app.run_test(size=(100, 40)) as pilot:
            await self.fill(pilot, "Example", "dc.example.com", "user", "saved-secret")
            self.app.query_one("#remember", Checkbox).value = True
            self.app.query_one("#save").press()
            await pilot.pause()
            self.assertEqual(self.app.query_one("#password", Input).value, "")
            self.assertIn("Connection and password saved",
                          str(self.app.query_one("#connection-status", Static).render()))
            self.app.query_one("#connect").press()
            await pilot.pause()
            await asyncio.wait_for(self.app.workers.wait_for_complete(), 5)
        self.assertEqual(self.connect.call_args.args[1], "saved-secret")

    async def test_entered_password_only_replaces_saved_password_when_checked(self):
        async with self.app.run_test(size=(100, 40)) as pilot:
            await self.fill(pilot, "Example", "dc.example.com", "user", "saved-secret")
            self.app.query_one("#remember", Checkbox).value = True
            self.app.query_one("#save").press()
            await pilot.pause()
            key = self.app.profiles["Example"]["credential_key"]
            self.app.query_one("#password", Input).value = "one-time-secret"
            await pilot.pause()
            self.app.query_one("#save").press()
            await pilot.pause()
            self.assertIn("password not saved", str(self.app.query_one("#connection-status", Static).render()))
            self.assertEqual(self.saved[key], "saved-secret")
            self.app.query_one("#connect").press()
            await pilot.pause()
            await asyncio.wait_for(self.app.workers.wait_for_complete(), 5)
        self.assertEqual(self.connect.call_args.args[1], "one-time-secret")
        self.assertEqual(self.saved[key], "saved-secret")

        app = ConnectionApp(self.connect, lambda user, key: self.saved[key],
                            lambda user, password, key: self.saved.update({key: password}), self.saved.pop,
                            profiles_path=self.path, legacy_path=self.legacy)
        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#password", Input).value = "replacement-secret"
            app.query_one("#remember", Checkbox).value = True
            app.query_one("#save").press()
            await pilot.pause()
            self.assertEqual(self.saved[key], "replacement-secret")
            self.assertEqual(app.query_one("#password", Input).value, "")

    async def test_failed_connection_stays_open_and_can_retry(self):
        self.connect.side_effect = [RuntimeError("Cannot connect"), ("conn", "directory", {"dn": "test"})]
        async with self.app.run_test(size=(100, 40)) as pilot:
            await self.fill(pilot, "Example", "dc.example.com", "user", "secret")
            self.app.query_one("#connect").press()
            await pilot.pause()
            await asyncio.wait_for(self.app.workers.wait_for_complete(), 5)
            self.assertIn("Cannot connect", str(self.app.query_one("#connection-status", Static).render()))
            self.app.query_one("#connect").press()
            await pilot.pause()
            await asyncio.wait_for(self.app.workers.wait_for_complete(), 5)
        self.assertEqual(self.app.return_value, ("conn", "directory", {"dn": "test"}, True, True))

    async def test_changing_server_resets_tls_and_stored_identity(self):
        async with self.app.run_test(size=(100, 40)) as pilot:
            await self.fill(pilot, "Example", "old.example.com", "user", "secret")
            self.app.query_one("#verified", Checkbox).value = False
            self.app.query_one("#remember", Checkbox).value = True
            self.app.query_one("#save").press()
            await pilot.pause()
            old_key = self.app.profiles["Example"]["credential_key"]
            self.app.query_one("#server", Input).value = "new.example.com"
            await pilot.pause()
            self.assertTrue(self.app.query_one("#verified", Checkbox).value)
            self.app.query_one("#password", Input).value = "new-secret"
            self.app.query_one("#remember", Checkbox).value = True
            self.app.query_one("#save").press()
            await pilot.pause()
            self.assertNotEqual(self.app.profiles["Example"]["credential_key"], old_key)

    async def test_switching_profiles_preserves_explicit_unverified_mode(self):
        async with self.app.run_test(size=(80, 24)) as pilot:
            await self.fill(pilot, "Unverified", "one.example.com", "user", "")
            self.app.query_one("#verified", Checkbox).value = False
            self.app.query_one("#save").press()
            await pilot.pause()
            self.app.query_one("#profiles", Select).value = ""
            await pilot.pause()
            self.assertTrue(self.app.query_one("#verified", Checkbox).value)
            await self.fill(pilot, "Verified", "two.example.com", "user", "")
            self.app.query_one("#save").press()
            await pilot.pause()
            self.app.query_one("#profiles", Select).value = "Unverified"
            await pilot.pause()
            self.assertFalse(self.app.query_one("#verified", Checkbox).value)
            self.assertIn("not verified", str(self.app.query_one("#tls-warning", Static).render()))

    async def test_unencrypted_connection_requires_confirmation(self):
        async with self.app.run_test(size=(100, 40)) as pilot:
            await self.fill(pilot, "Plain", "dc.example.com", "user", "secret")
            self.app.query_one("#transport", Select).value = "ldap"
            self.app.query_one("#remember", Checkbox).value = True
            await pilot.pause()
            self.assertTrue(self.app.query_one("#verified", Checkbox).disabled)
            self.assertIn("plaintext", str(self.app.query_one("#tls-warning", Static).render()))
            self.app.query_one("#connect").press()
            await pilot.pause()
            self.app.screen.query_one("#cancel").press()
            await pilot.pause()
            self.connect.assert_not_called()
            self.assertFalse(self.path.exists())
            self.assertEqual(self.saved, {})
            self.app.query_one("#connect").press()
            await pilot.pause()
            self.app.screen.query_one("#confirm").press()
            await pilot.pause()
            await asyncio.wait_for(self.app.workers.wait_for_complete(), 5)
        self.assertFalse(self.connect.call_args.args[0]["use_ssl"])
        self.assertFalse(load_profiles(self.path, self.legacy)[0]["Plain"]["use_ssl"])
        self.assertFalse(self.app.return_value[-1])

    async def test_changing_server_resets_unencrypted_protocol(self):
        async with self.app.run_test(size=(100, 40)) as pilot:
            await self.fill(pilot, "Plain", "old.example.com", "user", "")
            self.app.query_one("#transport", Select).value = "ldap"
            self.app.query_one("#save").press()
            await pilot.pause()
            self.assertFalse(self.app.profiles["Plain"]["use_ssl"])
            self.app.query_one("#profiles", Select).value = ""
            await pilot.pause()
            self.app.query_one("#profiles", Select).value = "Plain"
            await pilot.pause()
            self.assertEqual(self.app.query_one("#transport", Select).value, "ldap")
            self.app.query_one("#server", Input).value = "new.example.com"
            await pilot.pause()
            self.assertEqual(self.app.query_one("#transport", Select).value, "ldaps")
            self.assertTrue(self.app.query_one("#verified", Checkbox).value)

    async def test_forget_password_and_delete_profile_require_confirmation(self):
        async with self.app.run_test(size=(100, 40)) as pilot:
            await self.fill(pilot, "Example", "dc.example.com", "user", "secret")
            self.app.query_one("#remember", Checkbox).value = True
            self.app.query_one("#save").press()
            await pilot.pause()
            key = self.app.profiles["Example"]["credential_key"]
            self.app.query_one("#forget").press()
            await pilot.pause()
            self.app.screen.query_one("#cancel").press()
            await pilot.pause()
            self.assertIn(key, self.saved)
            self.app.query_one("#forget").press()
            await pilot.pause()
            self.app.screen.query_one("#confirm").press()
            await pilot.pause()
            self.assertNotIn(key, self.saved)
            self.assertFalse(self.app.profiles["Example"]["password_stored"])
            self.app.query_one("#delete").press()
            await pilot.pause()
            self.app.screen.query_one("#confirm").press()
            await pilot.pause()
            self.assertEqual(self.app.profiles, {})
            self.assertEqual(load_profiles(self.path, self.legacy), ({}, None))

    async def test_imported_profile_can_use_legacy_password(self):
        self.legacy.write_text(json.dumps({
            "server": "dc.example.com", "bind_user": "user", "tls_verified": False,
        }))
        self.saved["user"] = "legacy-secret"
        app = ConnectionApp(self.connect, lambda user, key: self.saved[key],
                            lambda user, password, key: self.saved.update({key: password}), lambda key: None,
                            profiles_path=self.path, legacy_path=self.legacy)
        async with app.run_test(size=(100, 40)) as pilot:
            self.assertIn("service=ad-directory, account=user",
                          str(app.query_one("#credential-info", Static).render()))
            app.query_one("#connect").press()
            await pilot.pause()
            await asyncio.wait_for(app.workers.wait_for_complete(), 5)
        self.assertEqual(self.connect.call_args.args[1], "legacy-secret")
        profile = load_profiles(self.path, self.legacy)[0]["Imported connection"]
        self.assertTrue(profile["password_stored"])
        self.assertEqual(self.saved[profile["credential_key"]], "legacy-secret")
        self.assertNotIn("legacy_credential_key", profile)
        self.assertEqual(self.saved["user"], "legacy-secret")
        self.assertTrue(self.legacy.exists())

    async def test_changed_bind_user_cannot_reuse_old_stored_password(self):
        async with self.app.run_test(size=(100, 40)) as pilot:
            await self.fill(pilot, "Example", "dc.example.com", "first-user", "secret")
            self.app.query_one("#remember", Checkbox).value = True
            self.app.query_one("#save").press()
            await pilot.pause()
            self.app.query_one("#bind-user", Input).value = "second-user"
            self.app.query_one("#connect").press()
            await pilot.pause()
            self.assertIn("enter a password", str(self.app.query_one("#connection-status", Static).render()))
            self.assertEqual(self.app.profiles["Example"]["bind_user"], "first-user")
            self.connect.assert_not_called()

    async def test_checkbox_labels_render_at_standard_terminal_size(self):
        async with self.app.run_test(size=(80, 24)) as pilot:
            for widget_id, label in (
                ("verified", "Verify TLS certificate and hostname"),
                ("remember", "Save password to credential manager"),
            ):
                widget = self.app.query_one(f"#{widget_id}", Checkbox)
                widget.focus()
                await pilot.pause()
                screenshot = html.unescape(self.app.export_screenshot()).replace("\N{NO-BREAK SPACE}", " ")
                self.assertGreaterEqual(widget.content_region.height, 1)
                self.assertIn(label, screenshot)
            self.app.query_one("#profiles", Select).focus()
            await pilot.pause()
            current = self.app.query_one("#profiles", Select).query_one("SelectCurrent")
            self.assertGreaterEqual(current.content_region.width, len("Imported connection"))


if __name__ == "__main__":
    unittest.main()
