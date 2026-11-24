"""Read-only LDAP access for directory browsing and user/group lookup."""

from threading import RLock

from ldap3 import ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, BASE, LEVEL, SUBTREE
from ldap3.utils.conv import escape_filter_chars


DIRECTORY_FILTER = (
    "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domainDNS)"
    "(&(objectCategory=person)(objectClass=user))(objectCategory=group)"
    "(objectCategory=computer))"
)
OBJECT_FILTERS = {
    "user": "(&(objectCategory=person)(objectClass=user))",
    "group": "(objectCategory=group)",
    "computer": "(objectCategory=computer)",
}


def search_type_filter(object_type):
    if object_type == "all":
        return "(|" + "".join(OBJECT_FILTERS.values()) + ")"
    if object_type not in OBJECT_FILTERS:
        raise RuntimeError(f"Unsupported search object type: {object_type!r}.")
    return OBJECT_FILTERS[object_type]


def object_kind(attributes):
    classes = attributes.get("objectClass", [])
    if isinstance(classes, str):
        classes = [classes]
    classes = {value.casefold() for value in classes}
    return next((kind for cls, kind in (
        ("organizationalunit", "OU"), ("domaindns", "Domain"),
        ("container", "Container"), ("group", "Group"),
        ("computer", "Computer"), ("user", "User"),
    ) if cls in classes), "Object")


def account_disabled(attributes):
    value = attributes.get("userAccountControl")
    if isinstance(value, (list, tuple)):
        if not value:
            return False
        if len(value) != 1:
            raise RuntimeError("AD returned multiple userAccountControl values.")
        value = value[0]
    if value is None:
        return False
    try:
        return bool(int(value) & 2)
    except (ValueError, TypeError) as error:
        raise RuntimeError("AD returned an invalid userAccountControl value.") from error


def directory_entry(entry):
    attributes = entry["attributes"]
    kind = object_kind(attributes)
    name = attributes.get("name", entry["dn"])
    if isinstance(name, list):
        name = name[0] if name else entry["dn"]
    account_name = attributes.get("sAMAccountName", "")
    if isinstance(account_name, (list, tuple)):
        if len(account_name) > 1:
            raise RuntimeError("AD returned multiple sAMAccountName values.")
        account_name = account_name[0] if account_name else ""
    return {
        "dn": entry["dn"], "name": name, "kind": kind,
        "account_name": account_name if kind in ("User", "Group", "Computer") else "",
        "expandable": kind in ("OU", "Domain", "Container"),
        "disabled": kind in ("User", "Computer") and account_disabled(attributes),
    }


class ADDirectory:
    def __init__(self, connection):
        self.connection = connection
        self.lock = RLock()
        entries = self.search("", "(objectClass=*)", BASE, ["defaultNamingContext"])
        if len(entries) != 1:
            raise RuntimeError("LDAP server did not return one Root DSE entry.")
        context = entries[0]["attributes"].get("defaultNamingContext")
        if isinstance(context, list):
            if len(context) != 1:
                raise RuntimeError("LDAP server returned an invalid defaultNamingContext.")
            context = context[0]
        if not context:
            raise RuntimeError("LDAP server did not return a defaultNamingContext.")
        self.base_dn = context

    def search(self, dn, query, scope, attributes, size_limit=0, allow_ambiguous_limit=False):
        with self.lock:
            original_raise = self.connection.raise_exceptions
            try:
                if allow_ambiguous_limit:
                    self.connection.raise_exceptions = False
                self.connection.search(dn, query, search_scope=scope,
                                       attributes=attributes, size_limit=size_limit)
            finally:
                self.connection.raise_exceptions = original_raise
            entries = [entry for entry in (self.connection.response or []) if entry["type"] == "searchResEntry"]
            result = self.connection.result["result"]
            if result != 0 and not (allow_ambiguous_limit and result == 4 and len(entries) >= 2):
                raise RuntimeError(f"LDAP search failed: {self.connection.result}")
            return entries

    def close(self):
        with self.lock:
            self.connection.unbind()

    def read(self, dn):
        entries = self.search(dn, "(objectClass=*)", BASE,
                              [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
        if len(entries) != 1:
            raise RuntimeError(f"Could not read directory object {dn!r}.")
        return {"dn": entries[0]["dn"], "attributes": entries[0]["attributes"]}

    def lookup(self, name, object_type="all"):
        type_filter = search_type_filter(object_type)
        escaped = escape_filter_chars(name)
        query = (
            "(|(&(objectCategory=person)(objectClass=user)"
            f"(|(sAMAccountName={escaped})(userPrincipalName={escaped})"
            f"(name={escaped})(cn={escaped})(displayName={escaped})))"
            "(&(objectCategory=group)"
            f"(|(sAMAccountName={escaped})(cn={escaped})))"
            "(&(objectCategory=computer)"
            f"(|(sAMAccountName={escaped})(cn={escaped})(dNSHostName={escaped}))))"
        )
        if object_type != "all":
            query = f"(&{type_filter}{query})"
        entries = self.search(self.base_dn, query, SUBTREE,
                              [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES], size_limit=2,
                              allow_ambiguous_limit=True)
        if not entries:
            raise RuntimeError(f"No AD user, group, or computer found for {name!r}.")
        if len(entries) != 1:
            raise RuntimeError(f"Multiple objects matched {name!r}; select one in the directory tree.")
        return {"dn": entries[0]["dn"], "attributes": entries[0]["attributes"]}

    def paged_entries(self, dn, query, scope, attributes):
        with self.lock:
            entries = list(self.connection.extend.standard.paged_search(
                dn, query, search_scope=scope, attributes=attributes,
                paged_size=500, generator=True,
            ))
            if self.connection.result["result"] != 0:
                raise RuntimeError(f"LDAP paged search failed: {self.connection.result}")
        return [entry for entry in entries if entry["type"] == "searchResEntry"]

    def children(self, dn):
        children = [
            directory_entry(entry) for entry in self.paged_entries(
                dn, DIRECTORY_FILTER, LEVEL,
                ["name", "objectClass", "userAccountControl", "sAMAccountName"],
            )
        ]
        return sorted(children, key=lambda item: (not item["expandable"], item["name"].casefold()))

    def find_names(self, name, matching="contains", object_type="all"):
        if not name.strip():
            raise RuntimeError("Enter a partial name to search for.")
        if matching not in {"contains", "starts"}:
            raise RuntimeError(f"Unsupported name matching mode: {matching!r}.")
        escaped = escape_filter_chars(name)
        pattern = f"{escaped}*" if matching == "starts" else f"*{escaped}*"
        query = (
            f"(&{search_type_filter(object_type)}"
            f"(|(name={pattern})(cn={pattern})(displayName={pattern})"
            f"(sAMAccountName={pattern})(dNSHostName={pattern})(userPrincipalName={pattern})))"
        )
        matches = []
        for entry in self.paged_entries(
            self.base_dn, query, SUBTREE,
            ["name", "displayName", "objectClass", "userAccountControl", "sAMAccountName"],
        ):
            match = directory_entry(entry)
            display_name = entry["attributes"].get("displayName")
            if isinstance(display_name, list):
                display_name = display_name[0] if display_name else ""
            if match["kind"] == "User" and display_name:
                match["name"] = display_name
            matches.append(match)
        return sorted(matches, key=lambda item: (item["name"].casefold(), item["dn"].casefold()))
