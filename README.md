# LDAP Directory

A read-only LDAP browser for users, groups, computers, domains, organizational units (OUs),
and containers in Active Directory. It connects to a configurable LDAP server
over LDAPS on port 636 by default, or unencrypted LDAP on port 389 if explicitly
selected. **There is no default server or bind account.**

TLS certificate and hostname verification is **enabled by default**. Use a
server hostname matching a certificate trusted by Python's system trust store.

## Setup

### macOS and Linux

Create a virtual environment and install dependencies in Bash:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

On Linux, use the password prompt or a private password file; native password
storage is currently supported only on macOS and Windows.

### Windows

Create a virtual environment and install dependencies in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Configure a connection

Launch the connection dialog:

```bash
.venv/bin/python ad_user_ldap.py
```

On Windows, use `.\.venv\Scripts\python.exe ad_user_ldap.py` instead.

Enter a connection name, server, bind identity (`DOMAIN\ACCOUNT` or a UPN), and
password. Choose **Connect** to save the profile and connect, or **Save** to
save it without connecting. To reuse a password, check **Save password to
credential manager**. Later, leave the password field blank to use the saved
password, or enter a different password for one use. Check **Save password**
again to replace it. The dialog shows the saved credential's service and account
names. Passwords are stored in macOS Keychain or Windows Credential Manager,
not in the settings file.

The connection selector supports multiple named profiles. Select **New
connection** to add one. **Delete** removes a profile but leaves its stored
password; use **Forget password** first if you also want to remove it. Changing
the server or bind user assigns a separate credential; it does not delete the
old stored password.

LDAPS and TLS verification are on by default. Unchecking **Verify TLS
certificate and hostname** exposes bind credentials to server impersonation.
Selecting **LDAP (no TLS, port 389)** sends the password and directory data
unencrypted and requires confirmation before connecting. Use these options
only if you accept their risks. Some Active Directory servers reject
unencrypted simple binds. Changing the server resets the protocol to verified
LDAPS. Profiles are saved in `~/.config/ad-directory/connections.json`
(`%USERPROFILE%\.config\ad-directory` on Windows), without passwords.

An existing `connection.json` is available in the dialog as **Imported
connection**. Leave the password blank to try its previously stored password.
That password is copied to a connection-specific credential entry when connecting;
the original settings and credential entry are not deleted. Legacy command-line
connection flags remain available and bypass the dialog; they continue to use
the old single connection settings.
Press `Ctrl+O` in the browser to reopen the dialog. Quitting the dialog returns
to the current directory; connecting to another profile opens its domain root.

## Browse

Open at a specific user, group, or computer:

```bash
.venv/bin/python ad_user_ldap.py "USER_ACCOUNT"
.venv/bin/python ad_user_ldap.py "GROUP_NAME"
.venv/bin/python ad_user_ldap.py "COMPUTER_NAME"
```

Or start at the domain root:

```bash
.venv/bin/python ad_user_ldap.py
```

The tree loads immediate children only when you expand a domain, OU, or
container, using paginated LDAP searches. Select a user, group, computer, or container to
show all attributes the bind account can read. Group attributes include direct
membership information returned by AD; this is not an effective-permissions or
transitive-membership report.

Searching for a user, group, or computer also expands its parent containers,
scrolls to the matching object, and focuses it in the directory tree. Only the
containers along that path are loaded; previously loaded branches are reused.

Use the search-mode dropdown to choose **Exact account/name**, **Contains
name**, or **Starts with name**. The adjacent type dropdown restricts any search
to **Users**, **Groups**, or **Computers**, or includes **All types**.
`Ctrl+N` selects Contains name and focuses the search box. Type part of
a full name, group name, computer/DNS name, or account name and press Enter.
Contains and Starts-with searches show an alphabetically sorted list with name, object type,
account name, and DN. Double-click a result or press Enter to open its properties
and select it in the tree. Esc cancels. Searches are paginated without a local
result cap, and search text is literal (not a user-supplied LDAP wildcard).
Exact searches also match a user's full display name or common name, in addition
to account/UPN, group, and computer names. Multiple exact matches are reported
explicitly.
Starts-with searches use `text*` instead of `*text*` and are generally more
index-friendly. Ends-with searching is not included as a speed optimization:
`*text` still has a leading wildcard, so it does not offer the same advantage.

User, group, and computer tree labels append their `sAMAccountName` after the
object type, for example `Display Name (User) - JDOE`. Computer account names
retain their trailing `$`. Containers and objects without a readable account
name have no suffix.

Disabled users and computers are dimmed and labeled `disabled` in the tree. Selecting one also
shows `Disabled account` in the header/status. This uses the `ACCOUNTDISABLE` bit
in `userAccountControl`, not account expiration or lockout status.

| Key | Action |
| --- | --- |
| `Ctrl+B` | Focus the directory tree |
| Option+1 / Alt+1 | Focus and highlight the directory pane |
| Option+2 / Alt+2 | Focus and highlight the Common attributes pane |
| Option+3 / Alt+3 | Focus and highlight the Other attributes pane |
| Option+Left / Alt+Left | Go back to the previous directory object |
| Option+Right / Alt+Right | Go forward to the next directory object |
| `Ctrl+T` | Move the selected attribute between Common and Other |
| Arrow keys / Space | Navigate and expand/collapse tree nodes |
| Enter | Select a directory object, or open the selected attribute's value dialog |
| `/` | Focus the user/group/computer search box; Enter searches |
| `Ctrl+N` | Switch to Contains name search and focus the search box |
| `Ctrl+O` | Open the connection dialog |
| `Ctrl+F` | Filter the current object's attribute names and values |
| Esc | Close the value dialog, or focus the attribute table |
| Tab / Shift+Tab | Move between widgets |
| `q` / `Ctrl+Q` | Quit (`Ctrl+Q` also works in text inputs) |

The directory tree is on the left. The attribute area on the right is split
vertically: Common attributes on top and Other attributes below, both with
Attribute, Count, and Value columns. Long values are shortened in the tables.
Common starts with a default set of identity, contact, membership, computer,
and account-status attributes, with separate defaults for users and other
object types. Select an attribute in either table and press `Ctrl+T` to move it
to the other table; focus follows the moved attribute. Choices are separate for
users, computers, and groups, and apply to all objects of the same type.
Domains, OUs, and other objects have a separate shared layout.
Choices are saved across restarts in
`~/.config/ad-directory/common-attributes.json` (attribute names only, no AD
values). Existing shared choices become the starting layout for each type;
subsequent changes affect only the currently viewed type. The attribute filter
applies to both tables.
Back/forward includes tree selections, searches, and relationship drilldowns.
It rereads the selected object and navigates to it in the tree. Visiting a new
object after going back replaces the forward history; refreshing the same
object does not add a duplicate. History lasts for the current TUI session.
Back/forward is disabled while an attribute dialog is open.
Ghostty on macOS sends Option+Left/Right as word-navigation escape sequences.
Textual interprets these as Ctrl+Left/Right; the TUI accepts those keys for
back/forward too, without changing Ghostty's settings.
The focused pane has a double accent-colored border. On macOS, configure your
terminal's Option key to send Alt/Esc sequences for the Option shortcuts.
Double-click an attribute (or select it and press Enter) to open a dialog showing its key and complete value,
including multi-valued properties. Close it with Esc or the Close button.
For `member`, `memberOf`, `directReports`, and `manager`, the dialog lists the
referenced objects. Double-click
an entry (or select it and press Enter) to close the dialog, display that object's
attributes, and navigate to it in the directory tree. A single click only selects
an entry. Attribute rows use the same double-click behavior: clicking an already
highlighted row once does not open it. Other attributes retain the full read-only
value viewer.
Relationship lists are sorted alphabetically by the referenced object's name,
ignoring case, rather than by LDAP's returned order.
Dates in the table and dialogs use readable month/day/year and time, with the
system's local timezone and UTC offset. AD generalized-time strings and known
Windows FILETIME attributes (such as `lastLogon`, `pwdLastSet`, and
`accountExpires`) are converted; special values show `Never`, `Not locked out`,
or a password-change requirement as appropriate. Invalid timestamps are labeled
explicitly. Raw values remain unchanged for future editing and JSON exports.
The dialog keeps a separate copy of the selected value for future editing
support, but currently all values are read-only. The directory-access layer
(`ad_directory.py`) and presentation (`ad_user_tui.py`) are separate so editing
can be added later; no LDAP write operations are implemented.

## JSON output

```bash
.venv/bin/python ad_user_ldap.py "USER_ACCOUNT" --connection "Office" --use-stored-credentials --json
.venv/bin/python ad_user_ldap.py "GROUP_NAME" --connection "Office" --use-stored-credentials --json > group.json
```

Computers can be found by name, DNS hostname, or their full `sAMAccountName`
(usually ending in `$`).

Replace `Office` with a saved profile name. `--connection` bypasses the dialog;
omit `--use-stored-credentials` to prompt for a password instead.
For legacy command-line server settings, `--ldap` selects unencrypted LDAP
for that invocation only; named profiles use their saved protocol instead.
Redirected output automatically uses JSON even without `--json`. A target user,
group, or computer is required for JSON output. Binary values are represented as objects
with `encoding: "base64"` and a `value` field.

## Other password sources

For command-line use, omit `--use-stored-credentials` to prompt for the bind
password. Alternatively, use a private password file with a saved profile:

```bash
chmod 600 .ldap-password
.venv/bin/python ad_user_ldap.py "USER_ACCOUNT" --connection "Office" --password-file .ldap-password
```

The file must contain one password line and be readable only by its owner on
macOS/Linux. Prefer the native OS credential store over a plaintext password
file; never commit credentials or exported directory data.

## Limits

- Requires network access to the configured directory.
- Searches the server's default naming context, not every domain in the forest.
- Only populated, readable attributes are returned; protected passwords cannot
  be retrieved.
- Tree listings include OUs, containers, domain objects, users, groups, and computers.
- Native credential storage uses macOS Keychain or Windows Credential Manager;
  other platforms can use a password prompt or a private password file.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```
