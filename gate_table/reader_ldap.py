"""An LDAP operation read into operations on `attribute@entry`. Software, holds no rule.

    read_ldap(op, schema) -> {(right, "attribute@dn", None), ...}

`op` is `{"op": "add" | "modify" | "delete" | "modrdn", "dn": ..., ...}`:
- `add`: `attributes` (name -> values). Reads as `add` on `entry@dn`, `add` on `children@parent`, and `add` on each
  attribute it sets (`objectClass` included);
- `modify`: `changes` (a list of `[attribute, "add" | "replace" | "delete", values]`). Each change reads with the
  right it needs: adding values `add`, taking values away `delete`, replacing them `write` (both);
- `delete`: reads as `delete` on `entry@dn` and `delete` on `children@parent`;
- `modrdn`: `newrdn` (and `newsuperior`, optional). Reads as `rename` on `entry@dn`, `delete` on the old parent's
  `children`, `add` on the new parent's `children`, and `write` on the naming attribute of the new RDN.

DNs are read as LDAP compares them: attribute types without case; the values of the types used here (`dc`, `ou`,
`cn`, `uid`) without case and with spaces around them dropped; an escaped character kept as it is. A DN that cannot be
read (an empty RDN, a missing `=`, a multi-valued RDN with `+`) raises `ValueError`: what is not read does not pass.
"""
import re

_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9-]*\Z")


def _split(dn, sep):
    out, cur, i = [], "", 0
    while i < len(dn):
        ch = dn[i]
        if ch == "\\" and i + 1 < len(dn):
            cur += dn[i:i + 2]
            i += 2
            continue
        if ch == sep:
            out.append(cur)
            cur = ""
        else:
            cur += ch
        i += 1
    out.append(cur)
    return out


def norm_dn(dn):
    if not isinstance(dn, str) or not dn.strip():
        raise ValueError("an empty DN")
    rdns = []
    for rdn in _split(dn, ","):
        if "+" in rdn.replace("\\+", ""):
            raise ValueError(f"a multi-valued RDN is not read: {rdn!r}")
        t, eq, v = rdn.partition("=")
        t, v = t.strip(), v.strip()
        if not eq or not _TYPE.match(t) or not v:
            raise ValueError(f"an RDN that cannot be read: {rdn!r}")
        rdns.append(f"{t.lower()}={v.lower()}")
    return ",".join(rdns)


def parent(dn):
    return dn.split(",", 1)[1] if "," in dn else ""


def read_ldap(op, schema=None):
    if not isinstance(op, dict):
        raise ValueError("an operation is an object")
    if isinstance(op.get("details"), dict):          # the door's form: op, dn and the rest under details
        op = {**op["details"], "op": op.get("op"), "dn": op.get("dn")}
    kind, dn = op.get("op"), norm_dn(op.get("dn"))
    ops = set()
    if kind == "add":
        attrs = op.get("attributes") or {}
        if not isinstance(attrs, dict) or not attrs:
            raise ValueError("an add with no attributes")
        ops |= {("add", f"entry@{dn}", None), ("add", f"children@{parent(dn)}", None)}
        ops |= {("add", f"{a.lower()}@{dn}", None) for a in attrs}
    elif kind == "modify":
        changes = op.get("changes") or []
        if not changes:
            raise ValueError("a modify with no change")
        for c in changes:
            if not isinstance(c, (list, tuple)) or len(c) != 3 or c[1] not in ("add", "replace", "delete"):
                raise ValueError(f"a change that cannot be read: {c!r}")
            right = {"add": "add", "delete": "delete", "replace": "write"}[c[1]]   # a value added, taken away, or both
            ops.add((right, f"{str(c[0]).lower()}@{dn}", None))
    elif kind == "delete":
        ops |= {("delete", f"entry@{dn}", None), ("delete", f"children@{parent(dn)}", None)}
    elif kind == "modrdn":
        new = norm_dn(op.get("newrdn"))
        if "," in new:
            raise ValueError("a new RDN with more than one part")
        sup = norm_dn(op["newsuperior"]) if op.get("newsuperior") else parent(dn)
        ops |= {("rename", f"entry@{dn}", None), ("delete", f"children@{parent(dn)}", None),
                ("add", f"children@{sup}", None), ("write", f"{new.split('=', 1)[0]}@{new},{sup}", None)}
    else:
        raise ValueError(f"an operation that is not read: {kind!r}")
    return ops


def ldap_rule(pattern, name):
    """Matcher for the table's ordered rules: `pattern` is {"dn", "scope": exact|children|subtree, "attrs"?}."""
    attr, _, dn = name.partition("@")
    pdn = norm_dn(pattern["dn"])
    scope = pattern.get("scope", "subtree")
    inside = dn == pdn if scope == "exact" else dn.endswith("," + pdn) if scope == "children" else (dn == pdn or dn.endswith("," + pdn))
    attrs = pattern.get("attrs")
    return inside and (attrs is None or attr in [a.lower() for a in attrs])
