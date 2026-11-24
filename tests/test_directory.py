import unittest
from threading import RLock
from unittest.mock import Mock

from ldap3 import Connection, MOCK_SYNC, Server

from ad_directory import ADDirectory, account_disabled, object_kind


class DirectoryTests(unittest.TestCase):
    def setUp(self):
        server = Server("directory.example")
        self.connection = Connection(server, client_strategy=MOCK_SYNC, check_names=False, raise_exceptions=True)
        self.connection.strategy.add_entry("DC=example,DC=com", {"objectClass": ["domainDNS"], "dc": ["example"]})
        self.connection.bind()
        self.directory = object.__new__(ADDirectory)
        self.directory.connection = self.connection
        self.directory.lock = RLock()
        self.directory.base_dn = "DC=example,DC=com"

    def add_user(self, cn, account, display):
        self.connection.strategy.add_entry(
            f"CN={cn},DC=example,DC=com",
            {"objectClass": ["top", "person", "user"], "objectCategory": ["person"],
             "cn": [cn], "name": [cn], "sAMAccountName": [account], "displayName": [display]},
        )

    def test_exact_lookup_full_display_name_account_and_common_name(self):
        self.add_user("Jane Example", "jexample", "Jane Q Example")
        for target in ("Jane Q Example", "jexample", "Jane Example"):
            with self.subTest(target=target):
                self.assertEqual(self.directory.lookup(target)["dn"], "CN=Jane Example,DC=example,DC=com")

    def test_duplicate_names_report_ambiguity_even_at_size_limit(self):
        for index in range(3):
            self.add_user(f"User {index}", f"user{index}", "Shared Name")
        with self.assertRaisesRegex(RuntimeError, "Multiple objects matched"):
            self.directory.lookup("Shared Name")
        self.assertTrue(self.connection.raise_exceptions)

    def test_existing_group_and_computer_identifiers_and_type_filter(self):
        self.connection.strategy.add_entry(
            "CN=Team,DC=example,DC=com",
            {"objectClass": ["top", "group"], "objectCategory": ["group"],
             "cn": ["Team"], "sAMAccountName": ["team-account"]},
        )
        self.connection.strategy.add_entry(
            "CN=PC1,DC=example,DC=com",
            {"objectClass": ["top", "computer"], "objectCategory": ["computer"],
             "cn": ["PC1"], "sAMAccountName": ["PC1$"], "dNSHostName": ["pc1.example.com"]},
        )
        for value, kind, expected in (
            ("team-account", "group", "Team"), ("Team", "group", "Team"),
            ("PC1$", "computer", "PC1"), ("pc1.example.com", "computer", "PC1"),
        ):
            with self.subTest(value=value):
                self.assertEqual(self.directory.lookup(value, kind)["dn"], f"CN={expected},DC=example,DC=com")
        with self.assertRaisesRegex(RuntimeError, "No AD"):
            self.directory.lookup("Team", "computer")

    def test_server_limit_with_fewer_than_two_results_is_an_error(self):
        self.directory.connection = Mock(
            raise_exceptions=True,
            result={"result": 4, "description": "sizeLimitExceeded"},
            response=[{"type": "searchResEntry", "dn": "CN=Only"}],
        )
        with self.assertRaisesRegex(RuntimeError, "sizeLimitExceeded"):
            self.directory.lookup("user")
        self.assertTrue(self.directory.connection.raise_exceptions)

    def test_size_limit_result_with_two_entries_is_ambiguous(self):
        self.directory.connection = Mock(
            raise_exceptions=True, result={"result": 4, "description": "sizeLimitExceeded"},
            response=[{"type": "searchResEntry", "dn": "CN=One"}, {"type": "searchResEntry", "dn": "CN=Two"}],
        )
        with self.assertRaisesRegex(RuntimeError, "Multiple objects matched"):
            self.directory.lookup("user")
        self.assertTrue(self.directory.connection.raise_exceptions)

    def test_ldap_errors_are_not_hidden(self):
        self.directory.connection = Mock(
            raise_exceptions=True, result={"result": 50, "description": "insufficientAccessRights"},
            response=None,
        )
        with self.assertRaisesRegex(RuntimeError, "insufficientAccessRights"):
            self.directory.lookup("user")
        self.assertTrue(self.directory.connection.raise_exceptions)

    def test_exact_search_escapes_filter_characters(self):
        self.directory.connection = Mock(raise_exceptions=True, result={"result": 0}, response=[])
        with self.assertRaisesRegex(RuntimeError, "No AD"):
            self.directory.lookup("a*)(cn=*)")
        query = self.directory.connection.search.call_args.args[1]
        self.assertIn(r"(displayName=a\2a\29\28cn=\2a\29)", query)

    def test_computer_class_and_disabled_flag(self):
        self.assertEqual(object_kind({"objectClass": ["top", "user", "computer"]}), "Computer")
        self.assertTrue(account_disabled({"userAccountControl": ["4098"]}))
        self.assertFalse(account_disabled({"userAccountControl": ["4096"]}))


if __name__ == "__main__":
    unittest.main()
