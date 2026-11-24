"""Is this document a table the engine can read? (the format: docs/FORMAT.md)

    problems(table) -> list of sentences, empty when the table can be read

Only the form is checked: the keys, the kinds of condition and what each needs, the names a condition refers to.
Whether a rule is the right one is answered by trying it on the log, never here.
"""

TYPES = ("string", "number", "integer", "list", "object")

# what each kind of condition needs besides `if` and `else`
KINDS = {
    "record_exists": ("record", "id"),
    "state_in": ("record", "id", "states"),
    "linked_state_in": ("record", "id", "linked", "through", "states"),
    "record_field_max": ("record", "id", "field", "max"),
    "arg_max": ("arg", "max"),
    "arg_in_list": ("arg", "list"),
    "arg_ends_with": ("arg", "value"),
    "time_between": ("from", "to"),
    "actor_not_field": ("record", "id", "field"),
    "address_allowed": ("address", "port"),
    "no_planted_value": ("values",),
    "expr": ("expr",),
}


def _condition(c, where, door, table, out):
    if not isinstance(c, dict) or c.get("if") not in KINDS:
        out.append(f"{where}: a condition needs \"if\", one of {', '.join(KINDS)}")
        return
    if not isinstance(c.get("else"), str) or not c["else"].strip():
        out.append(f"{where}: a condition needs \"else\", the reason given to the agent when it fails")
    for k in KINDS[c["if"]]:
        if k not in c:
            out.append(f"{where}: {c['if']} needs \"{k}\"")
        elif isinstance(c[k], str) and not c[k].strip():
            out.append(f"{where}: \"{k}\" is empty")
    form = (door or {}).get("form", {})
    for k in ("arg", "id", "address", "port"):
        if door is not None and isinstance(c.get(k), str) and c[k] not in form:
            out.append(f"{where}: \"{c[k]}\" is not a field of the function's form")
    if c["if"] in ("state_in", "linked_state_in") and not (isinstance(c.get("states"), list) and c.get("states")):
        out.append(f"{where}: \"states\" is a list with at least one state")
    if c["if"] in ("arg_max", "record_field_max") and not isinstance(c.get("max"), (int, float)):
        out.append(f"{where}: \"max\" is a number")
    if "decoy" in c and not (isinstance(c["decoy"], str) and c["decoy"].strip()):
        out.append(f"{where}: \"decoy\" is the text the agent reads instead of the reason, and it is not empty")
    if c["if"] == "no_planted_value" and "values" in c:
        v = c["values"]
        if not (isinstance(v, list) and v and all(isinstance(x, str) and len(x) >= 8 for x in v)):
            out.append(f"{where}: \"values\" is a list of planted values, each a text of at least 8 characters")
    if c["if"] == "expr" and isinstance(c.get("expr"), str):
        try:
            import celpy
            celpy.Environment().compile(c["expr"])
        except Exception as e:  # noqa: BLE001
            out.append(f"{where}: the expression is not read: {str(e).splitlines()[0][:160]}")


def problems(table):
    out = []
    if not isinstance(table, dict) or not isinstance(table.get("doors"), dict) or not table["doors"]:
        return ["a table needs \"doors\": the functions and language doors the agent may use"]
    for i, c in enumerate(table.get("every_door", []) or []):
        _condition(c, f"every door, condition {i + 1}", None, table, out)
    cs = table.get("containers", {})
    for key, c in (cs.items() if isinstance(cs, dict) else enumerate(cs if isinstance(cs, list) else [])):
        if isinstance(c, dict) and "decoy" in c and not (isinstance(c["decoy"], str) and c["decoy"].strip()):
            out.append(f"container {key}: \"decoy\" is the text the agent reads instead of the reason, and it is not empty")
    for name, d in table["doors"].items():
        if not isinstance(d, dict):
            out.append(f"{name}: a door is an object")
            continue
        form = d.get("form", {})
        if not isinstance(form, dict) or any(t not in TYPES for t in form.values()):
            out.append(f"{name}: \"form\" gives each field one of {', '.join(TYPES)}")
        if "decoy" in d and not ("closed" in d and isinstance(d["decoy"], str) and d["decoy"].strip()):
            out.append(f"{name}: a door's \"decoy\" answers its \"closed\": a closed door and a text that is not empty")
        ways = [k for k in ("requires", "closed", "language") if k in d]
        if len(ways) > 1:
            out.append(f"{name}: a door has one of \"requires\", \"closed\", \"language\", not {' and '.join(ways)}")
        if "closed" in d and (not isinstance(d["closed"], str) or not d["closed"].strip()):
            out.append(f"{name}: \"closed\" is the reason given to the agent")
        if "language" in d and d.get("arg") != "*" and d.get("arg") not in form:
            out.append(f"{name}: a language door names in \"arg\" the field that holds the text")
        if not isinstance(d.get("requires", []), list):
            out.append(f"{name}: \"requires\" is a list of conditions")
            continue
        for i, c in enumerate(d.get("requires", [])):
            _condition(c, f"{name}, condition {i + 1}", d, table, out)
        if isinstance(d.get("bind"), dict) and d["bind"]:
            from .engine import bind_order
            try:
                bind_order(d["bind"])                  # read by what each name needs, never by the order of the keys
            except ValueError as e:
                out.append(f"{name}: {e}")
    for block in ("counters", "switches"):              # the gate keeps no memory of a session
        if table.get(block):
            out.append(f"{block}: the gate keeps no {block[:-1] if block == 'counters' else 'switch'}. A count or a state a rule reads is a field of "
                       "the company's object, read with a condition on that record")
    containers = table.get("containers")
    for name, c in (containers.items() if isinstance(containers, dict) else []):
        gone = sorted(k for k in c if k.endswith("_session")) if isinstance(c, dict) else []
        if gone:
            out.append(f"container {name}: {', '.join(gone)}: nothing is summed over a session; a limit is stated per statement (`_max`)")
    return out
