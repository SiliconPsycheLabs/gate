"""The shape of an action: the same operation on the same container asked in the same form.

A shape holds no value of the call. For a function it is the function's name and the fields it carries; for a
language door it is what the reader returned, with the parts that carry values (a counting query, a number of
files) taken out. The same door, the same arguments and the same table always give the same shape, and the same
shape always gives the same key. No model, no score, no word list: only the table and the reader's output.

    shape_of(table, door, args, ops=None, unread=False, matchers=None) -> dict
    shape_key(shape) -> 32 hex characters
    primary(shape)   -> (operation, container): one of read, write, delete, execute, or "" when not declared
    form_text(shape) -> the form in a few words, for a list and for search
    action_text(table, door, args) -> the action as asked, on one line
"""
import hashlib
import json

OPERATIONS = ("read", "write", "delete", "execute")

# What each kind a reader returns is, among the four operations. A table may add
# kinds of its own, or change one, with "operation_of": {"kind": "read" | "write" | "delete" | "execute"}.
OPERATION_OF = {
    "read": "read", "any": "read",
    "insert": "write", "update": "write", "replace": "write", "write": "write", "read+write": "write",
    "create": "write", "rewrite": "write", "permissions": "write", "update_rows": "write",
    "channel": "write", "channel_pattern": "write",
    "delete": "delete", "delete_rows": "delete", "delete_absent": "delete", "destroy_files": "delete",
    "destroy_dirs": "delete", "structure": "delete",
    "execute": "execute",
}
_COUNTS = ("statements", "commands")                    # how many statements a text holds: form, not an operation
_VALUE_PARTS = ("update_rows", "delete_rows", "destroy_files")   # their third part is a query or a number
_RANK = {"delete": 4, "write": 3, "execute": 2, "read": 1, "": 0}


def _pattern_of(table, kind, name, matchers):
    """Where containers are patterns (keys, refs, object names), the shape names the pattern, never the object."""
    match = (matchers or {}).get(table.get("container_match"))
    if match is None or kind == "command":
        return name if kind == "command" else "(unmatched)"
    if kind in ("channel", "channel_pattern"):
        for p in table.get("channels", ()):
            if p == name or match(p, name):
                return p
        return "(unmatched)"
    cs = table.get("containers", {})
    for c in (cs if isinstance(cs, dict) else [p for c in cs for p in ([c["match"]] if "match" in c else c.get("resources", []))]):
        if match(c, name):
            return c
    return "(unmatched)"


def shape_of(table, door, args, ops=None, unread=False, matchers=None):
    d = (table.get("doors") or {}).get(door) or {}
    language = d.get("language")
    if not language:
        s = {"kind": "function", "door": door, "fields": sorted(str(k) for k in (args or {}))}
        for k in ("operation", "container"):
            if d.get(k):
                s[k] = d[k]
        return s
    s = {"kind": language, "door": door}
    if unread or ops is None:
        s["unread"] = True
        return s
    out = set()
    for kind, name, part in ops:
        if kind in _COUNTS:
            out.add((kind, "", f"{name}/{part}"))
            continue
        if table.get("container_match"):
            name = _pattern_of(table, kind, name, matchers)
        out.add((kind, str(name), "" if kind in _VALUE_PARTS or part is None else str(part)))
    s["ops"] = [list(o) for o in sorted(out)]
    return s


def shape_key(shape):
    return hashlib.sha256(json.dumps(shape, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def _operation(table, kind):
    return (table.get("operation_of") or {}).get(kind) or OPERATION_OF.get(kind, "")


def primary(shape, table=None):
    """The operation and the container a row is listed under: the heaviest operation of the shape."""
    if shape.get("kind") == "function":
        op = shape.get("operation", "")
        return (op if op in OPERATIONS else "", str(shape.get("container", "")))
    found = []
    for kind, name, _part in shape.get("ops", []):
        if kind in _COUNTS or kind == "command":
            continue
        op = _operation(table or {}, kind)
        found.append((_RANK.get(op, 0), name, op if op in OPERATIONS else ""))
    if not found:
        return ("", "")
    top = max(f[0] for f in found)
    name, op = min((f[1], f[2]) for f in found if f[0] == top)
    return (op, name)


def form_text(shape):
    if shape.get("kind") == "function":
        return f"{shape['door']}({', '.join(shape.get('fields', []))})"
    if shape.get("unread"):
        return "not read by the reader"
    parts = []
    for kind, name, part in shape.get("ops", []):
        if kind in _COUNTS:
            if not part.startswith("1/"):
                parts.append(f"{kind} {part.split('/')[0]}")
            continue
        parts.append(f"{kind} {name}" + (f".{part}" if part else ""))
    return "; ".join(parts)


def action_text(table, door, args):
    d = (table.get("doors") or {}).get(door) or {}
    if d.get("language"):
        v = args if d.get("arg") == "*" else (args or {}).get(d.get("arg"))
        return v if isinstance(v, str) else json.dumps(v, sort_keys=True, default=str)
    inner = ", ".join(f"{k}={json.dumps(v, default=str) if not isinstance(v, str) else v}" for k, v in (args or {}).items())
    return f"{door}({inner})"
