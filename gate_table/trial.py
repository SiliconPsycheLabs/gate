"""A table tried on recorded actions: the same action, in the state and with the reads of its record.

    try_rows(table, rows) -> one result per row
        row:    {"id", "door", "args", "reads", "state", "opened"}
        result: [id, passes, reason, missing, alone]
            passes   the table lets the action through, in the state it was recorded in (openings included)
            reason   the fixed reason when it does not
            missing  the record did not hold something the table reads: the row could not be tried
            alone    for an action a person had opened: whether the table lets it through without the opening

Pure and deterministic: no database, no network, no model. It runs in a process of its own (the caller's event
loop never waits on it).
"""
from .recorder import again


def try_rows(table, rows):
    out = []
    for r in rows:
        why, missing = again(table, r["door"], r["args"], r["reads"], r["state"])
        alone = None
        if r.get("opened"):
            alone = again(table, r["door"], r["args"], r["reads"], r["state"], openings=False)[0] is None
        out.append([r["id"], why is None, why or "", bool(missing), alone])
    return out


def affected(base, draft):
    """The doors whose answers can differ between two tables: None means every door (something outside the doors
    changed: a counter, a switch, a container, a condition of every door)."""
    skip = ("doors", "version", "source", "table")
    if {k: v for k, v in base.items() if k not in skip} != {k: v for k, v in draft.items() if k not in skip}:
        return None
    a, b = base.get("doors", {}), draft.get("doors", {})
    return sorted(d for d in set(a) | set(b) if a.get(d) != b.get(d))
