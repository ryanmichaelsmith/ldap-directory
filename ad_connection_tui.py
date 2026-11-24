"""Startup connection profile editor."""

import asyncio

from ldap3.core.exceptions import LDAPException
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Footer, Input, Select, Static

from ad_connections import (
    CREDENTIAL_SERVICE, load_profiles, new_credential_key, save_profiles, validate_bind_user,
    validate_profile_name, validate_server,
)


class ConfirmDialog(ModalScreen[bool]):
    CSS = """
    ConfirmDialog { align: center middle; }
    #confirmation { width: 65; height: auto; padding: 1 2; border: thick $primary; background: $surface; }
    #confirmation-text { height: auto; margin-bottom: 1; }
    #confirmation-buttons { height: 3; }
    """
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, message):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="confirmation"):
            yield Static(self.message, id="confirmation-text", markup=False)
            with Horizontal(id="confirmation-buttons"):
                yield Button("Confirm", id="confirm", variant="error")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed):
        self.dismiss(event.button.id == "confirm")

    def action_cancel(self):
        self.dismiss(False)


class ConnectionApp(App):
    CSS = """
    Screen { align: center middle; }
    #connection-form { width: 80; max-width: 100%; height: auto; max-height: 100%; border: solid $primary; padding: 0 1; }
    .field { height: 3; }
    .field > Static { width: 17; height: 3; content-align: left middle; }
    .field > Input, .field > Select { width: 1fr; }
    #verified, #remember { height: 3; }
    #tls-warning { height: auto; color: $warning; }
    #password-hint, #credential-info { height: auto; }
    #connection-status { height: auto; min-height: 1; color: $warning; }
    #connection-buttons { height: auto; }
    #connection-buttons Button { margin-right: 1; min-width: 0; width: auto; }
    """
    BINDINGS = [
        Binding("escape", "quit", "Quit"),
        Binding("ctrl+c", "quit", "Quit", show=False, priority=True),
        Binding("ctrl+q", "quit", "Quit", show=False, priority=True),
    ]
    TITLE = "LDAP Directory - Connections"

    def __init__(self, connect, get_password, put_password, delete_password,
                 profiles_path=None, legacy_path=None):
        super().__init__()
        self.connect = connect
        self.get_password = get_password
        self.put_password = put_password
        self.delete_password = delete_password
        options = {}
        if profiles_path is not None:
            options["path"] = profiles_path
        if legacy_path is not None:
            options["legacy_path"] = legacy_path
        self.profiles, self.selected = load_profiles(**options)
        self.profiles_path = profiles_path
        self.connecting = False

    def choices(self):
        return [("New connection", "")] + [(name, name) for name in sorted(self.profiles, key=str.casefold)]

    def compose(self) -> ComposeResult:
        profile = self.profiles.get(self.selected, {})
        with VerticalScroll(id="connection-form"):
            with Horizontal(classes="field"):
                yield Static("Connection")
                yield Select(self.choices(), value=self.selected or "", allow_blank=False, id="profiles")
            with Horizontal(classes="field"):
                yield Static("Name")
                yield Input(value=self.selected or "", placeholder="Connection name", id="name")
            with Horizontal(classes="field"):
                yield Static("Server")
                yield Input(value=profile.get("server", ""), placeholder="dc.example.com", id="server")
            with Horizontal(classes="field"):
                yield Static("Bind user")
                yield Input(value=profile.get("bind_user", ""), placeholder=r"DOMAIN\account or UPN", id="bind-user")
            yield Checkbox("Verify TLS certificate and hostname", value=profile.get("tls_verified", True), id="verified")
            yield Static(
                "" if profile.get("tls_verified", True) else "Warning: server identity is not verified.",
                id="tls-warning",
            )
            with Horizontal(classes="field"):
                yield Static("Password")
                yield Input(password=True, placeholder="Enter password", id="password")
            yield Static("", id="password-hint", markup=False)
            yield Checkbox("Save password to credential manager", id="remember")
            yield Static("", id="credential-info", markup=False)
            yield Static("", id="connection-status", markup=False)
            with Horizontal(id="connection-buttons"):
                yield Button("Connect", id="connect", variant="primary")
                yield Button("Save", id="save")
                yield Button("Delete", id="delete", variant="error")
                yield Button("Forget password", id="forget")
                yield Button("Quit", id="quit")
        yield Footer()

    def status(self, message):
        self.query_one("#connection-status", Static).update(message)

    def on_mount(self):
        self.query_one("#connection-form", VerticalScroll).border_title = "Connections"
        self.update_password_info()
        self.query_one("#profiles" if self.selected else "#name").focus()

    def write_profiles(self, profiles, selected):
        if self.profiles_path is None:
            save_profiles(profiles, selected)
        else:
            save_profiles(profiles, selected, self.profiles_path)
        self.profiles, self.selected = profiles, selected

    def load_form(self, name):
        profile = self.profiles.get(name, {})
        self.selected = name or None
        self.query_one("#name", Input).value = name
        self.query_one("#server", Input).value = profile.get("server", "")
        self.query_one("#bind-user", Input).value = profile.get("bind_user", "")
        self.query_one("#verified", Checkbox).value = profile.get("tls_verified", True)
        self.query_one("#password", Input).value = ""
        self.query_one("#remember", Checkbox).value = False
        self.update_password_info()
        self.status("")

    def on_select_changed(self, event: Select.Changed):
        if event.select.id == "profiles" and isinstance(event.value, str):
            if event.value == event.select.value and event.value != (self.selected or ""):
                self.load_form(event.value)

    def on_input_changed(self, event: Input.Changed):
        if event.input.id == "server":
            profile = self.profiles.get(self.selected, {})
            if profile and event.value.casefold() != profile["server"].casefold():
                self.query_one("#verified", Checkbox).value = True
        if event.input.id in {"server", "bind-user", "password"}:
            self.update_password_info()

    def update_password_info(self):
        profile = self.profiles.get(self.selected, {})
        server = self.query_one("#server", Input).value
        user = self.query_one("#bind-user", Input).value
        password = self.query_one("#password", Input).value
        identity_changed = bool(profile) and (
            profile["server"].casefold() != server.casefold()
            or profile["bind_user"].casefold() != user.casefold()
        )
        legacy_key = profile.get("legacy_credential_key")
        has_saved = profile.get("password_stored", False) or bool(legacy_key)
        if identity_changed:
            hint = "Server or bind user changed; enter a password for the new connection."
        elif password:
            hint = (
                "The entered password will be used. Check Save password to replace the saved password."
                if has_saved else "The entered password will be used. Check Save password to store it."
            )
        elif legacy_key:
            hint = "Leave blank to try the previously stored password, or enter a new password."
        elif has_saved:
            hint = "Leave blank to use the saved password, or enter a new password."
        else:
            hint = "Enter a password to connect. Check Save password to store it."
        self.query_one("#password-hint", Static).update(hint)
        key = legacy_key or (profile.get("credential_key") if profile.get("password_stored") else None)
        label = "Previous credential" if identity_changed else "Credential"
        if legacy_key:
            label = "Legacy credential (if present)"
        self.query_one("#credential-info", Static).update(
            f"{label}: service={CREDENTIAL_SERVICE}, account={key}" if key else ""
        )
        self.query_one("#forget", Button).disabled = self.connecting or not has_saved

    def on_checkbox_changed(self, event: Checkbox.Changed):
        if event.checkbox.id == "verified":
            self.query_one("#tls-warning", Static).update(
                "" if event.value else "Warning: server identity is not verified."
            )

    def update_choices(self, selected):
        widget = self.query_one("#profiles", Select)
        widget.set_options(self.choices())
        widget.value = selected or ""

    def save_form(self, connecting=False):
        name = validate_profile_name(self.query_one("#name", Input).value)
        server = validate_server(self.query_one("#server", Input).value)
        user = validate_bind_user(self.query_one("#bind-user", Input).value)
        verified = self.query_one("#verified", Checkbox).value
        password = self.query_one("#password", Input).value
        remember = self.query_one("#remember", Checkbox).value
        if any(existing.casefold() == name.casefold() and existing != self.selected for existing in self.profiles):
            raise RuntimeError(f"A connection named {name!r} already exists.")
        old = self.profiles.get(self.selected, {})
        identity_changed = bool(old) and (
            old["server"].casefold() != server.casefold() or old["bind_user"].casefold() != user.casefold()
        )
        if remember and not password:
            raise RuntimeError("Enter a password before selecting Save password.")
        has_saved = not identity_changed and (
            old.get("password_stored", False) or bool(old.get("legacy_credential_key"))
        )
        if connecting and not password and not has_saved:
            if identity_changed:
                raise RuntimeError("Server or bind user changed; enter a password for the new identity.")
            raise RuntimeError("Enter a password to connect.")
        source = "input" if password else "stored"
        credential_key = new_credential_key() if not old or identity_changed else old["credential_key"]
        legacy_key = None if identity_changed else old.get("legacy_credential_key")
        stored = old.get("password_stored", False) if not identity_changed else False
        if connecting and source == "stored" and legacy_key:
            password = self.get_password(user, legacy_key)
            self.put_password(user, password, credential_key)
            legacy_key = None
            source = "input"
            stored = True
        if remember:
            self.put_password(user, password, credential_key)
            stored = True
            legacy_key = None
        profile = {
            "server": server, "bind_user": user, "tls_verified": verified,
            "credential_key": credential_key, "password_stored": stored,
        }
        if legacy_key:
            profile["legacy_credential_key"] = legacy_key
        profiles = dict(self.profiles)
        if self.selected and self.selected != name:
            del profiles[self.selected]
        profiles[name] = profile
        self.write_profiles(profiles, name)
        self.update_choices(name)
        self.query_one("#remember", Checkbox).value = False
        if remember and not connecting:
            self.query_one("#password", Input).value = ""
        self.update_password_info()
        return profile, source, password

    def on_button_pressed(self, event: Button.Pressed):
        button = event.button.id
        if button == "quit":
            self.action_quit()
        elif button in {"save", "connect"}:
            try:
                remembering = self.query_one("#remember", Checkbox).value
                profile, source, password = self.save_form(connecting=button == "connect")
                if button == "connect":
                    self.connect_profile(profile, source, password)
                else:
                    self.status(
                        "Connection and password saved." if remembering else
                        "Connection saved; entered password not saved." if password else "Connection saved."
                    )
            except (OSError, RuntimeError, ValueError) as error:
                self.status(str(error))
        elif button in {"delete", "forget"}:
            if not self.selected:
                self.status("Select a saved connection first.")
                return
            message = (
                f"Delete {self.selected!r}? Stored passwords are not deleted; use Forget password first."
                if button == "delete" else (
                    "Delete the legacy password? This also affects the old command-line settings."
                    if self.profiles[self.selected].get("legacy_credential_key")
                    else f"Delete the stored password for {self.selected!r}?"
                )
            )
            self.push_screen(ConfirmDialog(message), lambda confirmed: self.confirm_action(button, confirmed))

    def confirm_action(self, action, confirmed):
        if not confirmed:
            return
        try:
            profiles = dict(self.profiles)
            if action == "delete":
                del profiles[self.selected]
                self.write_profiles(profiles, None)
                self.update_choices(None)
                self.load_form("")
                self.status("Connection deleted. Stored passwords were not deleted.")
            else:
                profile = dict(profiles[self.selected])
                self.delete_password(profile.pop("legacy_credential_key", profile["credential_key"]))
                profile["password_stored"] = False
                profiles[self.selected] = profile
                self.write_profiles(profiles, self.selected)
                self.update_password_info()
                self.status("Stored password deleted.")
        except (OSError, RuntimeError, ValueError) as error:
            self.status(str(error))

    @work(exclusive=True, group="connect")
    async def connect_profile(self, profile, source, password):
        self.connecting = True
        for button in self.query(Button):
            button.disabled = True
        self.status(
            "Connecting with TLS verification disabled..." if not profile["tls_verified"] else "Connecting..."
        )
        try:
            if source == "stored":
                password = await asyncio.to_thread(
                    self.get_password, profile["bind_user"], profile["credential_key"]
                )
            connection, directory, record = await asyncio.to_thread(self.connect, profile, password)
            self.exit((connection, directory, record, profile["tls_verified"]))
        except (LDAPException, OSError, RuntimeError, ValueError) as error:
            self.status(f"Connection failed: {error}")
        finally:
            self.connecting = False
            for button in self.query(Button):
                button.disabled = False
            self.update_password_info()

    def action_quit(self):
        if not self.connecting:
            self.exit()
