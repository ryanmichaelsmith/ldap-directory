import contextlib
import io
import json
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import ad_user_ldap as cli


class ConnectionSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "connection.json"
        self.settings_patch = patch.object(cli, "CONNECTION_SETTINGS_PATH", self.path)
        self.settings_patch.start()
        self.addCleanup(self.settings_patch.stop)

    def test_tls_choice_persists_and_new_server_defaults_to_verified(self):
        user = r"EXAMPLE\user"
        self.assertEqual(cli.resolve_connection_settings(user, "dc.example.com"), (user, "dc.example.com", True))
        self.assertEqual(cli.resolve_connection_settings(None, None, tls_verified=False)[2], False)
        self.assertFalse(cli.resolve_connection_settings(None, "DC.EXAMPLE.COM")[2])
        self.assertFalse(cli.resolve_connection_settings("other-user", None)[2])
        self.assertTrue(cli.resolve_connection_settings(None, "dc2.example.com")[2])
        self.assertFalse(cli.resolve_connection_settings(None, "dc3.example.com", tls_verified=False)[2])
        self.assertTrue(cli.resolve_connection_settings(None, None, tls_verified=True)[2])
        self.assertEqual(json.loads(self.path.read_text())["tls_verified"], True)

    def test_existing_settings_default_to_verified(self):
        self.path.write_text(json.dumps({"bind_user": "user", "server": "dc.example.com"}))
        self.assertTrue(cli.resolve_connection_settings(None, None)[2])

    def test_invalid_setting_does_not_get_silently_trusted(self):
        self.path.write_text(json.dumps({"bind_user": "user", "server": "dc.example.com", "tls_verified": "false"}))
        with self.assertRaisesRegex(RuntimeError, "tls_verified"):
            cli.resolve_connection_settings(None, None)

    def test_missing_server_and_identity(self):
        with self.assertRaisesRegex(RuntimeError, "No bind user"):
            cli.resolve_connection_settings(None, None)
        with self.assertRaisesRegex(RuntimeError, "No LDAP server"):
            cli.resolve_connection_settings("user", None)
        self.assertFalse(self.path.exists())

    def test_server_change_does_not_inherit_orphaned_insecure_mode(self):
        self.path.write_text(json.dumps({"bind_user": "user", "tls_verified": False}))
        self.assertTrue(cli.resolve_connection_settings(None, "new.example.com")[2])

    def test_tls_flags_are_mutually_exclusive(self):
        for flags in (("--tls-verified", "--tls-unverified"), ("--ldap", "--tls-unverified")):
            with self.subTest(flags=flags), \
                 patch("sys.argv", ["ad_user_ldap.py", *flags]), \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    cli.main()
                self.assertEqual(result.exception.code, 2)

    def test_cli_wires_tls_and_does_not_leak_warning_into_json(self):
        connection = Mock(bound=True)
        connection.bind.return_value = True
        directory = Mock()
        directory.lookup.return_value = {"dn": "CN=User,DC=example", "attributes": {}}
        for flag, expected in (("--tls-verified", ssl.CERT_REQUIRED), ("--tls-unverified", ssl.CERT_NONE)):
            with self.subTest(flag=flag), \
                 patch("sys.argv", ["ad_user_ldap.py", "user", "--json", "--server", "dc.example.com",
                                    "--bind-user", "user", flag]), \
                 patch.object(cli, "bind_password", return_value="not-a-real-password"), \
                 patch.object(cli, "Tls") as tls, patch.object(cli, "Server") as server, \
                 patch.object(cli, "Connection", return_value=connection), \
                 patch.object(cli, "ADDirectory", return_value=directory), \
                 contextlib.redirect_stdout(io.StringIO()) as stdout, \
                 contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(cli.main(), 0)
                self.assertEqual(tls.call_args.kwargs["validate"], expected)
                self.assertEqual(server.call_args.kwargs["port"], 636)
                self.assertTrue(server.call_args.kwargs["use_ssl"])
                self.assertEqual(json.loads(stdout.getvalue())["dn"], "CN=User,DC=example")
                self.assertEqual("Warning:" in stderr.getvalue(), flag == "--tls-unverified")

    def test_unencrypted_ldap_uses_port_389_and_warns_without_polluting_json(self):
        connection = Mock(bound=True)
        connection.bind.return_value = True
        directory = Mock()
        directory.lookup.return_value = {"dn": "CN=User,DC=example", "attributes": {}}
        with patch("sys.argv", ["ad_user_ldap.py", "user", "--json", "--server", "dc.example.com",
                                "--bind-user", "user", "--ldap"]), \
             patch.object(cli, "bind_password", return_value="not-a-real-password"), \
             patch.object(cli, "Tls") as tls, patch.object(cli, "Server") as server, \
             patch.object(cli, "Connection", return_value=connection), \
             patch.object(cli, "ADDirectory", return_value=directory), \
             contextlib.redirect_stdout(io.StringIO()) as stdout, \
             contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(cli.main(), 0)
        tls.assert_not_called()
        self.assertEqual(server.call_args.kwargs["port"], 389)
        self.assertFalse(server.call_args.kwargs["use_ssl"])
        self.assertNotIn("tls", server.call_args.kwargs)
        self.assertEqual(json.loads(stdout.getvalue())["dn"], "CN=User,DC=example")
        self.assertIn("unencrypted", stderr.getvalue())
        self.assertNotIn("use_ssl", json.loads(self.path.read_text()))


if __name__ == "__main__":
    unittest.main()
