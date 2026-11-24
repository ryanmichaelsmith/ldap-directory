"""Read-only AD directory browser and attribute viewer."""

import asyncio
import copy
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from ldap3.core.exceptions import LDAPException
from ldap3.utils.dn import parse_dn, to_dn
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Click
from textual.screen import ModalScreen
from textual.worker import Worker, get_current_worker
from textual.widgets import Button, DataTable, Footer, Header, Input, Select, Static, TextArea, Tree

from ad_directory import account_disabled, object_kind
from ad_settings import CONFIG_DIRECTORY, write_settings


FILETIME_ATTRIBUTES = {
    "accountexpires", "badpasswordtime", "lastlogon", "lastlogoff",
    "lastlogontimestamp", "lockouttime", "pwdlastset",
    "msds-userpasswordexpirytimecomputed",
    "msds-lastsuccessfulinteractivelogontime", "msds-lastfailedinteractivelogontime",
    "msds-keyapproximatelastlogontimestamp",
}
GENERALIZED_TIME_ATTRIBUTES = {
    "whencreated", "whenchanged", "createtimestamp", "modifytimestamp",
    "dscorepropagationdata", "msds-entry-time-to-die",
    "msds-localeffectiverecycletime", "msexchwhenmailboxcreated", "msexchwhensoftdeleted",
}
DEFAULT_COMMON_ATTRIBUTES = {
    "name", "displayname", "samaccountname", "userprincipalname", "mail",
    "telephonenumber", "title", "department", "manager",
    "directreports", "member", "memberof", "dnshostname", "operatingsystem",
    "lastlogontimestamp", "pwdlastset", "accountexpires", "badpasswordtime",
    "lockouttime",
}
COMMON_ATTRIBUTE_TYPES = ("user", "computer", "group", "other")
DEFAULT_COMMON_BY_TYPE = {
    **{kind: DEFAULT_COMMON_ATTRIBUTES for kind in COMMON_ATTRIBUTE_TYPES},
    "user": (DEFAULT_COMMON_ATTRIBUTES - {"lastlogontimestamp"})
    | {"lastlogon", "whencreated", "whenchanged"},
}


def load_common_attributes(path):
    try:
        contents = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {kind: set(DEFAULT_COMMON_BY_TYPE[kind]) for kind in COMMON_ATTRIBUTE_TYPES}
    except OSError as error:
        raise RuntimeError(f"Could not read attribute preferences {path}: {error}") from error
    try:
        names = json.loads(contents)
    except ValueError as error:
        raise RuntimeError(f"Invalid attribute preferences {path}: {error}") from error
    if isinstance(names, list):
        names = {kind: names for kind in COMMON_ATTRIBUTE_TYPES}
    if not isinstance(names, dict) or set(names) - set(COMMON_ATTRIBUTE_TYPES):
        raise RuntimeError(f"Invalid attribute preferences {path}: expected attribute lists by object type.")
    preferences = {}
    for kind in COMMON_ATTRIBUTE_TYPES:
        values = names.get(kind, list(DEFAULT_COMMON_BY_TYPE[kind]))
        if not isinstance(values, list) or any(
            not isinstance(name, str) or not name.strip() for name in values
        ):
            raise RuntimeError(f"Invalid attribute preferences {path}: expected attribute names for {kind}.")
        preferences[kind] = {name.casefold() for name in values}
    return preferences


def save_common_attributes(path, preferences):
    write_settings(path, {kind: sorted(names) for kind, names in preferences.items()})


def readable_datetime(value):
    if value.tzinfo is None or value.utcoffset() is None:
        return value.strftime("%b %d, %Y %I:%M:%S %p") + " (timezone unspecified)"
    return value.astimezone().strftime("%b %d, %Y %I:%M:%S %p %Z (UTC%z)")


def display_value(attribute, value):
    if isinstance(value, (list, tuple)):
        return [display_value(attribute, item) for item in value]
    if isinstance(value, Mapping):
        return {
            key: display_value(key if isinstance(key, str) else "", item)
            for key, item in value.items()
        }
    if isinstance(value, datetime):
        return readable_datetime(value)
    if isinstance(value, date):
        return value.strftime("%b %d, %Y")
    name = attribute.casefold()
    if name in FILETIME_ATTRIBUTES:
        try:
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise ValueError("Invalid FILETIME type")
            ticks = int(value)
            if name in {"accountexpires", "msds-userpasswordexpirytimecomputed"} and (
                ticks == 9223372036854775807 or (ticks == 0 and name == "accountexpires")
            ):
                return "Never"
            if ticks == 0:
                if name in {"pwdlastset", "msds-userpasswordexpirytimecomputed"}:
                    return "Must change password at next logon"
                if name == "lockouttime":
                    return "Not locked out"
                return "Not set / never"
            if ticks < 0:
                raise ValueError("Negative FILETIME")
            timestamp = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
                microseconds=ticks // 10
            )
        except (ValueError, OverflowError):
            return f"{value} (invalid timestamp)"
        return readable_datetime(timestamp)
    if name in GENERALIZED_TIME_ATTRIBUTES:
        match = re.fullmatch(r"(\d{14})(?:\.\d+)?(Z|[+-]\d{4})", str(value))
        if match is None:
            return f"{value} (invalid timestamp)"
        try:
            timestamp = datetime.strptime(match[1] + match[2], "%Y%m%d%H%M%S%z")
        except ValueError:
            return f"{value} (invalid timestamp)"
        return readable_datetime(timestamp)
    return value


@dataclass
class DirectoryNode:
    dn: str
    expandable: bool = True
    loaded: bool = False
    loading: bool = False
    worker: Worker | None = None


class DoubleClickTable(DataTable):
    async def _on_click(self, event: Click):
        event.prevent_default()
        row = event.style.meta.get("row")
        if (
            event.button != 1 or row is None or not 0 <= row < self.row_count
            or event.style.meta.get("out_of_bounds", False)
        ):
            return
        self.move_cursor(row=row)
        if event.chain == 2:
            self.action_select_cursor()
        event.stop()


def relationship_sort_key(dn):
    name = parse_dn(dn)[0][1].encode("utf-8")
    name = re.sub(
        rb"\\([0-9a-fA-F]{2}|.)",
        lambda match: bytes([int(match[1], 16)]) if len(match[1]) == 2 else match[1],
        name,
    ).decode("utf-8")
    return name.casefold(), dn.casefold()


class AttributeDialog(ModalScreen[str]):
    CSS = """
    AttributeDialog { align: center middle; }
    #attribute-dialog { width: 85%; height: 80%; border: thick $primary; padding: 1 2; }
    #dialog-dn { height: auto; max-height: 4; }
    #dialog-key { height: auto; margin: 1 0; }
    #dialog-value { height: 1fr; }
    #dialog-members { height: 1fr; }
    #dialog-hint { height: auto; margin-bottom: 1; }
    #close-attribute { margin-top: 1; }
    """
    BINDINGS = [Binding("escape", "close", "Close", priority=True)]

    def __init__(self, dn, attribute, value, json_encoder, can_navigate=False):
        super().__init__()
        self.dn = dn
        self.attribute = attribute
        self.value = copy.deepcopy(value)
        self.value_text = json.dumps(
            display_value(attribute, self.value),
            indent=2, ensure_ascii=False, default=json_encoder
        )
        self.members = None
        self.relationship_error = None
        if can_navigate and attribute.casefold() in {
            "member", "members", "memberof", "directreports", "manager",
        }:
            values = self.value if isinstance(self.value, (list, tuple)) else [self.value]
            if all(isinstance(value, str) for value in values):
                try:
                    self.members = sorted(values, key=relationship_sort_key)
                except (LDAPException, UnicodeDecodeError) as error:
                    self.relationship_error = f"Could not sort related objects: {error}"

    def compose(self) -> ComposeResult:
        with Vertical(id="attribute-dialog"):
            yield Static(self.dn, id="dialog-dn", markup=False)
            yield Static(f"Key: {self.attribute} (read-only)", id="dialog-key", markup=False)
            if self.members is not None:
                yield Static(
                    "Double-click an entry or press Enter to open its object."
                    if self.members else "No related objects.",
                    id="dialog-hint", markup=False,
                )
                yield DoubleClickTable(id="dialog-members", cursor_type="row", show_header=False)
            else:
                yield TextArea(
                    self.value_text, read_only=True, show_line_numbers=True, id="dialog-value"
                )
            yield Button("Close", id="close-attribute", variant="primary")
        yield Footer()

    def on_mount(self):
        if self.members is not None:
            table = self.query_one("#dialog-members", DoubleClickTable)
            table.add_column("Distinguished name")
            for index, dn in enumerate(self.members):
                table.add_row(Text(dn), key=str(index))
            table.focus()
        else:
            self.query_one("#dialog-value", TextArea).focus()
        if self.relationship_error:
            self.notify(self.relationship_error, title="Invalid relationship value", severity="error")

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        if event.data_table.id == "dialog-members" and self.members is not None:
            event.stop()
            self.dismiss(self.members[int(event.row_key.value)])

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "close-attribute":
            self.action_close()

    def action_close(self):
        self.dismiss()


class SearchResultsDialog(ModalScreen[str]):
    CSS = """
    SearchResultsDialog { align: center middle; }
    #search-dialog { width: 90%; height: 80%; border: thick $primary; padding: 1 2; }
    #search-summary { height: auto; margin-bottom: 1; }
    #search-results { height: 1fr; }
    #close-search { margin-top: 1; }
    """
    BINDINGS = [Binding("escape", "close", "Close", priority=True)]

    def __init__(self, query, matches, matching="contains", object_type="all"):
        super().__init__()
        self.search_text = query
        self.results = matches
        self.match_description = "starting with" if matching == "starts" else "containing"
        self.scope = "all types" if object_type == "all" else object_type

    def compose(self) -> ComposeResult:
        with Vertical(id="search-dialog"):
            yield Static(
                f"{len(self.results)} matches ({self.scope}) {self.match_description} {self.search_text!r}."
                " Double-click a result or press Enter to open it."
                if self.results else f"No matches ({self.scope}) {self.match_description} {self.search_text!r}.",
                id="search-summary", markup=False,
            )
            yield DoubleClickTable(id="search-results", cursor_type="row")
            yield Button("Close", id="close-search")
        yield Footer()

    def on_mount(self):
        table = self.query_one("#search-results", DataTable)
        table.add_columns("Name", "Type", "Account", "Distinguished name")
        for index, match in enumerate(self.results):
            disabled = match.get("disabled", False)
            kind = match["kind"] + (" (disabled)" if disabled else "")
            table.add_row(*(
                Text(value, style="dim" if disabled else "")
                for value in (match["name"], kind, match["account_name"], match["dn"])
            ), key=str(index))
        table.focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        if event.data_table.id == "search-results":
            event.stop()
            self.dismiss(self.results[int(event.row_key.value)]["dn"])

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "close-search":
            self.action_close()

    def action_close(self):
        self.dismiss()


class ADUserApp(App):
    CSS = """
    #dn { height: auto; max-height: 4; padding: 0 1; }
    #dn.disabled { color: $text-muted; text-style: dim; }
    #filter { margin: 0 1; }
    #lookup { margin: 0 1; }
    #lookup-bar { height: 3; }
    #lookup-mode { width: 25; margin: 0 1; }
    #lookup-type { width: 17; margin-right: 1; }
    #status { height: 1; padding: 0 1; }
    #panes { height: 1fr; }
    #directory { width: 30%; height: 1fr; border: solid $primary; }
    #attribute-panes { width: 1fr; height: 1fr; }
    #attributes { width: 1fr; height: 1fr; border: solid $primary; }
    #other-attributes { width: 1fr; height: 1fr; border: solid $primary; }
    #directory:focus, #attributes:focus, #other-attributes:focus { border: double $accent; }
    """
    BINDINGS = [
        Binding("ctrl+f", "filter", "Filter"),
        Binding("escape", "table", "Attribute list"),
        Binding("ctrl+b", "browse", "Directory tree"),
        Binding("/", "find", "Find account/group"),
        Binding("ctrl+n", "find_name", "Name search"),
        Binding("ctrl+o", "connections", "Connections", priority=True),
        Binding("alt+1", "browse", "Directory pane", priority=True),
        Binding("alt+2", "table", "Attributes pane", priority=True),
        Binding("alt+3", "other", "Other attributes", priority=True),
        Binding("alt+left", "back", "Back", priority=True),
        Binding("alt+right", "forward", "Forward", priority=True),
        Binding("ctrl+left", "back", "Back", priority=True, show=False),
        Binding("ctrl+right", "forward", "Forward", priority=True, show=False),
        Binding("ctrl+t", "toggle_common", "Move attribute"),
        Binding("q", "quit", "Quit"),
        Binding("ctrl+q", "quit", "Quit", priority=True),
    ]

    def __init__(self, record, json_encoder, directory=None, preferences_path=None, tls_verified=True, use_ssl=True):
        super().__init__()
        self.directory = directory
        self.tls_verified = tls_verified
        self.use_ssl = use_ssl
        self.json_encoder = json_encoder
        self.preferences_path = (
            Path(preferences_path) if preferences_path is not None
            else CONFIG_DIRECTORY / "common-attributes.json"
        )
        self.common_by_type = load_common_attributes(self.preferences_path)
        self.set_record(record)
        self.history = [record["dn"]]
        self.history_index = 0
        self.history_target_index = None
        self.navigation_worker = None
        self.visible_names = []
        self.title = "AD Directory"

    def set_record(self, record):
        self.record = record
        self.attributes = dict(record["attributes"])
        kind = object_kind(self.attributes).casefold()
        self.object_type = kind if kind in {"user", "computer", "group"} else "other"
        self.common_attributes = self.common_by_type[self.object_type]
        self.disabled_user = account_disabled(self.attributes)
        self.sub_title = "Read-only | Disabled account" if self.disabled_user else "Read-only"
        self.attribute_names = sorted(self.attributes, key=str.casefold)
        self.display_attributes = {
            name: display_value(name, value) for name, value in self.attributes.items()
        }
        self.value_text = {
            name: json.dumps(value, indent=2, ensure_ascii=False, default=self.json_encoder)
            for name, value in self.display_attributes.items()
        }

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(self.record["dn"], id="dn", markup=False)
        if self.directory:
            with Horizontal(id="lookup-bar"):
                yield Select(
                    [
                        ("Exact account/name", "exact"), ("Contains name", "contains"),
                        ("Starts with name", "starts"),
                    ],
                    value="exact", allow_blank=False, id="lookup-mode",
                )
                yield Select(
                    [
                        ("All types", "all"), ("Users", "user"), ("Groups", "group"),
                        ("Computers", "computer"),
                    ],
                    value="all", allow_blank=False, id="lookup-type",
                )
                yield Input(
                    placeholder="User account, full name, group, or computer name; press Enter",
                    id="lookup",
                )
        yield Input(placeholder="Filter attribute names or values...", id="filter")
        yield Static(id="status", markup=False)
        with Horizontal(id="panes"):
            if self.directory:
                yield Tree(Text(self.directory.base_dn),
                           data=DirectoryNode(self.directory.base_dn), id="directory")
            with Vertical(id="attribute-panes"):
                yield DoubleClickTable(id="attributes", cursor_type="row")
                yield DoubleClickTable(id="other-attributes", cursor_type="row")
        yield Footer()

    def on_mount(self):
        self.main_screen = self.screen
        self.main_screen.query_one("#dn", Static).set_class(self.disabled_user, "disabled")
        for table_id, title in (
            ("attributes", "Common attributes (Option+2)"),
            ("other-attributes", "Other attributes (Option+3)"),
        ):
            table = self.main_screen.query_one(f"#{table_id}", DataTable)
            table.border_title = title
            table.add_columns("Attribute", "Count", "Value")
        self.populate("")
        if self.directory:
            tree = self.main_screen.query_one("#directory", Tree)
            tree.border_title = "Directory (Option+1)"
            tree.root.expand()
            if self.record["dn"].casefold() != self.directory.base_dn.casefold():
                self.navigation_worker = self.reveal_initial_record()
        self.action_table()

    @work(exclusive=True, group="selection")
    async def reveal_initial_record(self):
        try:
            await self.reveal_in_tree(self.record["dn"])
        except (LDAPException, OSError, RuntimeError) as error:
            self.notify(str(error), title="Tree navigation failed", severity="error", timeout=15)
            self.main_screen.query_one("#status", Static).update(f"Tree navigation failed: {error}")

    def populate(self, query):
        query = query.casefold()
        self.visible_names = [
            name for name in self.attribute_names
            if query in name.casefold() or query in self.value_text[name].casefold()
        ]
        for table_id, common in (("attributes", True), ("other-attributes", False)):
            table = self.main_screen.query_one(f"#{table_id}", DataTable)
            table.clear()
            for name in self.visible_names:
                if (name.casefold() in self.common_attributes) != common:
                    continue
                value = self.attributes[name]
                count = len(value) if isinstance(value, (list, tuple)) else 1
                preview = json.dumps(
                    self.display_attributes[name], ensure_ascii=False, default=self.json_encoder
                )
                if len(preview) > 80:
                    preview = preview[:77] + "..."
                table.add_row(Text(name), str(count), Text(preview), key=name)
            if table.row_count:
                table.move_cursor(row=0)
        disabled_status = " | Disabled account" if self.disabled_user else ""
        transport_status = (
            f"TLS certificate validation {'ON' if self.tls_verified else 'OFF'}"
            if self.use_ssl else "LDAP UNENCRYPTED"
        )
        self.main_screen.query_one("#status", Static).update(
            f"{len(self.visible_names)} / {len(self.attributes)} attributes{disabled_status}"
            f" | Read-only | {transport_status}"
        )

    def on_input_changed(self, event: Input.Changed):
        if event.input.id == "filter":
            self.populate(event.value)

    def on_input_submitted(self, event: Input.Submitted):
        if event.input.id == "lookup" and event.value.strip():
            mode = self.main_screen.query_one("#lookup-mode", Select).value
            object_type = self.main_screen.query_one("#lookup-type", Select).value
            if mode in {"contains", "starts"}:
                self.history_target_index = None
                self.navigation_worker = self.load_name_matches(event.value.strip(), mode, object_type)
                self.refresh_bindings()
            else:
                self.load_record(event.value.strip(), by_name=True, object_type=object_type)

    @work(exclusive=True, group="selection")
    async def load_name_matches(self, query, matching="contains", object_type="all"):
        description = "starting with" if matching == "starts" else "containing"
        self.main_screen.query_one("#status", Static).update(f"Searching {object_type} names {description} {query!r}...")
        try:
            matches = await asyncio.to_thread(self.directory.find_names, query, matching, object_type)
            self.main_screen.query_one("#status", Static).update(f"{len(matches)} name matches.")
            self.push_screen(
                SearchResultsDialog(query, matches, matching, object_type), self.open_related_object
            )
        except (LDAPException, OSError, RuntimeError) as error:
            self.notify(str(error), title="Name search failed", severity="error", timeout=15)
            self.main_screen.query_one("#status", Static).update(f"Name search failed: {error}")
        finally:
            if self.navigation_worker is get_current_worker():
                self.history_target_index = None
                self.refresh_bindings()

    def on_tree_node_expanded(self, event: Tree.NodeExpanded):
        self.start_loading_children(event.node)

    def start_loading_children(self, node):
        data = node.data
        if data and data.expandable and not data.loaded and not data.loading:
            data.loading = True
            data.worker = self.load_children(node)
        return data.worker if data else None

    async def reveal_in_tree(self, dn):
        tree = self.main_screen.query_one("#directory", Tree)
        parts = to_dn(dn)
        base_parts = to_dn(self.directory.base_dn)
        if len(parts) < len(base_parts) or [
            part.casefold() for part in parts[-len(base_parts):]
        ] != [part.casefold() for part in base_parts]:
            raise RuntimeError(f"Object is outside the browsed directory: {dn}")
        node = tree.root
        for index in range(len(parts) - len(base_parts) - 1, -1, -1):
            node.expand()
            worker = self.start_loading_children(node)
            if worker:
                await asyncio.shield(worker.wait())
            if not node.data.loaded:
                raise RuntimeError(f"Could not load the tree container: {node.data.dn}")
            wanted = [part.casefold() for part in parts[index:]]
            child = next((
                child for child in node.children
                if child.data and [
                    part.casefold() for part in to_dn(child.data.dn)
                ] == wanted
            ), None)
            if child is None:
                raise RuntimeError(f"Object is not visible in the directory tree: {','.join(parts[index:])}")
            node = child
        await tree.wait_for_refresh()
        tree.move_cursor(node)
        if self.screen is self.main_screen:
            tree.focus()

    @work
    async def load_children(self, node):
        data = node.data
        label = node.label.copy()
        node.set_label(Text(str(label) + " (loading...)"))
        try:
            children = await asyncio.to_thread(self.directory.children, data.dn)
            for child in children:
                disabled = child.get("disabled", False)
                kind = child["kind"] + (", disabled" if disabled else "")
                account_name = child.get("account_name")
                suffix = f" - {account_name}" if account_name else ""
                node.add(
                    Text(f"{child['name']} ({kind}){suffix}", style="dim" if disabled else ""),
                    data=DirectoryNode(child["dn"], expandable=child["expandable"]),
                    allow_expand=child["expandable"],
                )
            data.loaded = True
            node.allow_expand = bool(children)
        except (LDAPException, OSError, RuntimeError) as error:
            self.notify(str(error), title="Directory listing failed", severity="error", timeout=15)
            self.main_screen.query_one("#status", Static).update(f"Directory listing failed: {error}")
        finally:
            data.loading = False
            node.set_label(label)

    def on_tree_node_selected(self, event: Tree.NodeSelected):
        if event.node.data:
            self.load_record(event.node.data.dn)

    def load_record(self, target, by_name=False, reveal=False, history_index=None, object_type="all"):
        self.history_target_index = history_index
        self.navigation_worker = self._load_record(target, by_name, reveal, history_index, object_type)
        self.refresh_bindings()
        return self.navigation_worker

    @work(exclusive=True, group="selection")
    async def _load_record(self, target, by_name=False, reveal=False, history_index=None, object_type="all"):
        try:
            self.main_screen.query_one("#status", Static).update(f"Loading {target}...")
            try:
                operation = self.directory.lookup if by_name else self.directory.read
                options = {"object_type": object_type} if by_name else {}
                record = await asyncio.to_thread(operation, target, **options)
                self.set_record(record)
                self.main_screen.query_one("#dn", Static).update(record["dn"])
                self.main_screen.query_one("#dn", Static).set_class(self.disabled_user, "disabled")
                self.populate(self.main_screen.query_one("#filter", Input).value)
            except (LDAPException, OSError, RuntimeError) as error:
                self.notify(str(error), title="Object lookup failed", severity="error", timeout=15)
                self.main_screen.query_one("#status", Static).update(f"Object lookup failed: {error}")
                return
            if history_index is not None:
                self.history_index = history_index
            elif record["dn"].casefold() != self.history[self.history_index].casefold():
                del self.history[self.history_index + 1:]
                self.history.append(record["dn"])
                self.history_index = len(self.history) - 1
            if by_name or reveal:
                try:
                    await self.reveal_in_tree(record["dn"])
                except (LDAPException, OSError, RuntimeError) as error:
                    self.notify(str(error), title="Tree navigation failed", severity="error", timeout=15)
                    self.main_screen.query_one("#status", Static).update(f"Tree navigation failed: {error}")
        finally:
            if self.navigation_worker is get_current_worker():
                self.history_target_index = None
                self.refresh_bindings()

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        if event.data_table.id not in {"attributes", "other-attributes"}:
            return
        name = event.row_key.value
        if name in self.visible_names:
            if (
                self.navigation_worker is not None
                and self.navigation_worker.name == "load_name_matches"
                and not self.navigation_worker.is_finished
            ):
                self.navigation_worker.cancel()
                self.main_screen.query_one("#status", Static).update("Name search canceled.")
            self.push_screen(AttributeDialog(
                self.record["dn"], name, self.attributes[name], self.json_encoder,
                can_navigate=self.directory is not None,
            ), self.open_related_object)

    def open_related_object(self, dn):
        if dn:
            self.load_record(dn, reveal=True)

    def action_filter(self):
        self.main_screen.query_one("#filter", Input).focus()

    def check_action(self, action, parameters):
        if action in {"browse", "table", "other", "toggle_common", "back", "forward", "connections"} and isinstance(self.screen, ModalScreen):
            return False
        if action == "connections":
            return self.directory is not None
        if action in {"back", "forward"}:
            index = self.history_index if self.history_target_index is None else self.history_target_index
            return self.directory is not None and (
                index > 0 if action == "back" else index < len(self.history) - 1
            )
        if action == "toggle_common":
            return (
                isinstance(self.focused, DoubleClickTable)
                and self.focused.id in {"attributes", "other-attributes"}
                and self.focused.row_count > 0
            )
        return True

    def action_table(self):
        self.main_screen.query_one("#attributes", DataTable).focus()

    def action_connections(self):
        self.exit("connections")

    def action_other(self):
        self.main_screen.query_one("#other-attributes", DataTable).focus()

    def action_back(self):
        self.navigate_history(-1)

    def action_forward(self):
        self.navigate_history(1)

    def navigate_history(self, direction):
        action = "back" if direction < 0 else "forward"
        if not self.check_action(action, ()):
            return
        index = self.history_index if self.history_target_index is None else self.history_target_index
        index += direction
        self.load_record(self.history[index], reveal=True, history_index=index)

    def action_toggle_common(self):
        if not self.check_action("toggle_common", ()):
            return
        table = self.focused
        name = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        common = set(self.common_attributes)
        if name.casefold() in common:
            common.remove(name.casefold())
            destination = "other-attributes"
        else:
            common.add(name.casefold())
            destination = "attributes"
        preferences = {**self.common_by_type, self.object_type: common}
        try:
            save_common_attributes(self.preferences_path, preferences)
        except OSError as error:
            self.notify(str(error), title="Preference save failed", severity="error", timeout=15)
            self.main_screen.query_one("#status", Static).update(f"Preference save failed: {error}")
            return
        self.common_by_type = preferences
        self.common_attributes = common
        self.populate(self.main_screen.query_one("#filter", Input).value)
        target = self.main_screen.query_one(f"#{destination}", DataTable)
        row = next(index for index, row in enumerate(target.ordered_rows) if row.key.value == name)
        target.move_cursor(row=row)
        target.focus()

    def action_browse(self):
        if self.directory:
            self.main_screen.query_one("#directory", Tree).focus()

    def action_find(self):
        if self.directory:
            self.main_screen.query_one("#lookup", Input).focus()

    def action_find_name(self):
        if self.directory and self.screen is self.main_screen:
            self.main_screen.query_one("#lookup-mode", Select).value = "contains"
            self.action_find()
