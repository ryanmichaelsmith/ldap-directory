import asyncio
import tempfile
import threading
import unittest
from pathlib import Path

from textual.widgets import DataTable, Static, Tree

from ad_user_tui import ADUserApp, AttributeDialog, load_common_attributes


BASE = "DC=example,DC=com"
OU = "OU=People," + BASE
USER = "CN=Jane," + OU
GROUP = "CN=Team," + OU


class FakeDirectory:
    base_dn = BASE

    def __init__(self):
        self.reads = []
        self.fail = False

    def children(self, dn):
        if self.fail:
            raise RuntimeError("Directory unavailable")
        if dn == BASE:
            return [{"dn": OU, "name": "People", "kind": "OU", "expandable": True}]
        return [
            {"dn": USER, "name": "Jane", "kind": "User", "expandable": False},
            {"dn": GROUP, "name": "Team", "kind": "Group", "expandable": False},
        ]

    def read(self, dn):
        self.reads.append(dn)
        return {"dn": dn, "attributes": {"objectClass": ["group"], "name": ["Team"]}}


class TuiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "common.json"
        self.record = {
            "dn": USER,
            "attributes": {"objectClass": ["user"], "name": ["Jane"], "memberOf": [GROUP]},
        }

    async def settle(self, app, pilot):
        await pilot.pause()
        await asyncio.wait_for(app.workers.wait_for_complete(), 10)
        await pilot.pause()

    async def test_initial_target_is_revealed_without_extra_read(self):
        directory = FakeDirectory()
        app = ADUserApp(self.record, str, directory, preferences_path=self.path, tls_verified=False)
        async with app.run_test() as pilot:
            await self.settle(app, pilot)
            tree = app.query_one("#directory", Tree)
            self.assertEqual(tree.cursor_node.data.dn, USER)
            self.assertTrue(tree.cursor_node.parent.is_expanded)
            self.assertEqual(directory.reads, [])
            self.assertEqual(app.history, [USER])
            self.assertIn("validation OFF", str(app.query_one("#status", Static).render()))

    async def test_type_defaults_and_saved_preferences(self):
        defaults = load_common_attributes(self.path)
        self.assertIn("lastlogon", defaults["user"])
        self.assertNotIn("lastlogontimestamp", defaults["user"])
        self.assertIn("whencreated", defaults["user"])
        for kind in ("computer", "group", "other"):
            self.assertIn("lastlogontimestamp", defaults[kind])
            self.assertNotIn("lastlogon", defaults[kind])
            self.assertNotIn("description", defaults[kind])
        self.path.write_text('{"user": ["customAttribute"]}')
        preferences = load_common_attributes(self.path)
        self.assertEqual(preferences["user"], {"customattribute"})
        self.assertEqual(preferences["computer"], defaults["computer"])
        preferences["computer"].add("extra")
        self.assertNotIn("extra", preferences["group"])

    async def test_initial_tree_failure_keeps_record_visible(self):
        directory = FakeDirectory()
        directory.fail = True
        app = ADUserApp(self.record, str, directory, preferences_path=self.path)
        async with app.run_test() as pilot:
            await self.settle(app, pilot)
            self.assertEqual(app.record["dn"], USER)
            self.assertIn("Directory unavailable", str(app.query_one("#status", Static).render()))

    async def test_root_launch_does_not_start_reveal(self):
        directory = FakeDirectory()
        record = {"dn": BASE, "attributes": {"objectClass": ["domainDNS"]}}
        app = ADUserApp(record, str, directory, preferences_path=self.path)
        async with app.run_test() as pilot:
            await self.settle(app, pilot)
            self.assertIsNone(app.navigation_worker)
            self.assertEqual(app.query_one("#directory", Tree).cursor_node.data.dn, BASE)
            self.assertIn("validation ON", str(app.query_one("#status", Static).render()))

    async def test_connection_shortcut_returns_to_connection_dialog(self):
        app = ADUserApp(self.record, str, FakeDirectory(), preferences_path=self.path)
        async with app.run_test() as pilot:
            await self.settle(app, pilot)
            await pilot.press("ctrl+o")
        self.assertEqual(app.return_value, "connections")

    async def test_new_selection_cancels_pending_startup_reveal(self):
        entered = threading.Event()
        release = threading.Event()
        directory = FakeDirectory()
        original_children = directory.children

        def delayed_children(dn):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("Timed out waiting for test release")
            return original_children(dn)

        directory.children = delayed_children
        app = ADUserApp(self.record, str, directory, preferences_path=self.path)
        try:
            async with app.run_test() as pilot:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                app.load_record(GROUP)
                await pilot.pause()
                release.set()
                await self.settle(app, pilot)
                self.assertEqual(app.record["dn"], GROUP)
                self.assertNotEqual(app.query_one("#directory", Tree).cursor_node.data.dn, USER)
        finally:
            release.set()

    async def test_relationship_navigation_and_history(self):
        directory = FakeDirectory()
        app = ADUserApp(self.record, str, directory, preferences_path=self.path)
        async with app.run_test(size=(120, 40)) as pilot:
            await self.settle(app, pilot)
            table = app.query_one("#attributes", DataTable)
            row = next(i for i, item in enumerate(table.ordered_rows) if item.key.value == "memberOf")
            table.move_cursor(row=row)
            table.focus()
            await pilot.press("enter")
            self.assertIsInstance(app.screen, AttributeDialog)
            await pilot.press("enter")
            await self.settle(app, pilot)
            self.assertEqual(app.record["dn"], GROUP)
            self.assertEqual(app.query_one("#directory", Tree).cursor_node.data.dn, GROUP)
            self.assertEqual(app.history, [USER, GROUP])


if __name__ == "__main__":
    unittest.main()
