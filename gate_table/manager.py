"""The action manager: one action in, one answer out, and the record of it.

For each action, in this order: translate (the company's tool name and fields become a door and its form), form,
decide (the table, the gate's own small state, and the company's system through a view), answer (pass or not, with
the fixed reason), record (everything needed to ask the same question again later). Two outcomes, no queue.

Pure: no database, no web framework. The gate keeps nothing by session. The state the caller hands in is the owner's
openings in force for these rules, kept by the caller for the table and the exact action (not for a session), and
the caller writes the records to the log.

    rec, state = decide(table, {"tool": "erp.settleInvoice", "args": {"invoiceNo": "88"}}, view, state, translation)
    rec, state = ran(table, rec, view, state)                    # the company's system confirmed the action ran
    state = release(table, rec, state)                           # it did not run: an opening it held is given back
    why, state = open_once(table, door, args, by, view, state)   # a person opens one exact action, once

An opening is used once. When `decide` lets an action through because of an opening, the opening is held for that
answer (`state["held"]`): a second `decide` of the same action is answered by the table alone, `ran` spends the
opening, and if the action does not run `release` gives it back. So the caller records which answer holds which
opening (the service: the answer's `ref` on the opening's row), whichever session the answer was given in.

Fail closed, always: a tool not tied to a door, a tie nobody signed, a table or a reader that cannot be read, a
company system that does not answer, each ends in "does not pass" with its own fixed reason.
"""
import importlib

from .recorder import RecordingGate, SentView, matchers, restore, state_of
from .shape import action_text, form_text, primary, shape_key, shape_of
from .view import Guarded

DOWN = "the company's system did not answer: the action does not pass"
_READERS = (("sql", "reader_sql", "read_sql"), ("shell", "reader_shell", "read_shell"), ("redis", "reader_redis", "read_redis"),
            ("s3", "reader_s3", "read_s3"), ("git", "reader_git", "read_git"), ("sudo", "reader_sudo", "read_sudo"),
            ("url", "reader_url", "read_url"), ("path_read", "reader_path", "read_path_read"),
            ("path_write", "reader_path", "read_path_write"))


# Translators that look at the company's own system while they read a text: the shell resolves links and patterns on
# the disk. Run on our host they would read our disk, so for an action that comes with its objects the company's side
# reads the text and sends the operations, and the gate decides on those.
READ_BY_THE_COMPANY = ("shell",)


def _read_by_the_company(view):
    def reader(lang):
        def read(text, schema):
            got = view.ops(lang, text)
            if got is None:
                raise ValueError("this text is read on the company's side, and its reading was not sent")
            if isinstance(got, dict):
                raise ValueError(str(got.get("unread") or "not read"))
            return {tuple(o) for o in got}
        return read
    return {lang: reader(lang) for lang in READ_BY_THE_COMPANY}


def readers():
    """One reader per language whose parser is installed. A door in a language with no reader does not pass."""
    out = {}
    for lang, module, fn in _READERS:
        try:
            out[lang] = getattr(importlib.import_module("." + module, __package__), fn)
        except ImportError:
            pass
    return out


def translate(translation, tool, args):
    """The company's tool as a door of the table: (door, args, None), or (None, None, the fixed reason).

    translation: {tool name: {"door": name, "fields": {tool field: door field}, "signed_by": person}}; None when the
    agent already speaks the table's own names. An unsigned tie counts as no tie."""
    if translation is None:
        return tool, args, None
    row = translation.get(tool)
    if row is None:
        return None, None, "this tool is not tied to a function of the table"
    if not row.get("signed_by"):
        return None, None, "the tie of this tool to a function of the table is not signed"
    fields = row.get("fields", {})
    stray = sorted(k for k in args if k not in fields)
    if stray:
        return None, None, "field with no counterpart in the function's form: " + ", ".join(stray)
    return row["door"], {fields[k]: v for k, v in args.items()}, None


def _key(door, args):
    import json
    return json.dumps([door, args], sort_keys=True)


def _gate(table, state):
    gate = restore(RecordingGate(table, readers(), matchers()), state)
    gate.openers = dict((state or {}).get("openers", {}))
    gate.held = dict((state or {}).get("held", {}))       # openings held by an answer not confirmed yet: key -> opener
    return gate


def _state(gate):
    s = state_of(gate)
    live = {k: v for k, v in gate.openers.items() if k in gate.one_shot}
    if live:
        s["openers"] = live
    if gate.held:
        s["held"] = dict(gate.held)
    return s


def _stopped(gate, door, args, reason, rule, reads=None):
    """A record for an action that was stopped before, or outside, the table's own rules."""
    t = gate.t
    try:
        shape = shape_of(t, door, args, None, False, gate.matchers)
        op, container = primary(shape, t)
        extra = {"kind": shape["kind"], "operation": op, "container": container, "shape": shape, "shape_key": shape_key(shape),
                 "form": form_text(shape), "text": action_text(t, door, args)}
    except Exception:  # noqa: BLE001  an action that cannot even be given a shape is still recorded
        shape = {"kind": "function", "door": str(door), "fields": sorted(str(k) for k in (args or {}))}
        extra = {"kind": "function", "operation": "", "container": "", "shape": shape, "shape_key": shape_key(shape), "form": "",
                 "text": str(door)}
    return {"door": door, "args": args, "table": str(t.get("table", "")), "table_version": int(t.get("version", 0) or 0), "opening": "",
            "opened_by": "", "gate_state": state_of(gate), "outcome": "nopass", "reason": reason, "rule": rule,
            "reads": {"before": reads or {}}, **extra}


def decide(table, action, view, state=None, translation=None):
    """One action: (the record, the gate's state). The state changes only when an opening is held for this answer;
    counters and switches move only on `ran`."""
    tool, asked = str(action.get("tool", "")), action.get("args")
    asked = asked if isinstance(asked, dict) else {}
    gate = _gate(table, state)
    if isinstance(view, SentView):           # the objects came with the action: no translator of ours looks at a disk
        gate.readers = {**gate.readers, **_read_by_the_company(view)}
    door, args, why = translate(translation, tool, asked)
    if why:
        rec = _stopped(gate, tool, asked, why, "translation")
    else:
        guard = Guarded(view)
        try:
            rec = gate.ask(door, args, guard)
        except Exception as e:  # noqa: BLE001  a table or a reader that cannot be read lets nothing through
            rec = _stopped(gate, door, args, f"the table could not be read: {type(e).__name__}", "table")
        if guard.down:
            rec.update(outcome="nopass", reason=DOWN, rule="view", opening="", opened_by="")
            rec["reads"]["down"] = guard.down
            rec.pop("decoy", None)          # the rule did not decide: the system did not answer
    if rec["outcome"] == "pass" and rec.get("opening") == "once":    # the opening is held by this answer until ran or release
        key = _key(rec["door"], gate._last[1] if gate._last else rec["args"])
        if key in gate.one_shot:
            gate.one_shot.remove(key)
            gate.held[key] = gate.openers.pop(key, rec.get("opened_by") or "owner")
    if translation is not None:
        rec["tool"] = tool
    return rec, _state(gate)


def ran(table, rec, view, state=None, result=None):
    """The company's system confirmed that a passed action ran: counters and switches move, a one-shot opening is
    spent. If the system does not answer here, nothing is moved and ValueError is raised: the caller asks again."""
    if rec.get("outcome") != "pass":
        raise ValueError("only an action that passed can have run")
    gate = _gate(table, state)
    args = dict(rec["args"])
    gate.form(rec["door"], args)
    gate._last = (rec["door"], args)
    key = _key(rec["door"], args)
    if rec.get("opening") == "once":                 # an answer given by an opening: the opening must still be held for it
        if key not in gate.held:
            raise ValueError("the opening this answer used is spent or was given back: ask again")
        gate.one_shot.append(key)                    # put back for the engine, which spends it as it runs
        gate.openers[key] = gate.held.pop(key)
    guard = Guarded(view)
    out = gate.ran(rec, guard, result)
    if guard.down:                                   # the caller keeps the state it had: nothing moved, the opening is still held
        raise ValueError(DOWN)
    return out, _state(gate)


def release(table, rec, state=None):
    """The action did not run (the agent gave up, the company's system refused, the caller timed out): an opening
    the answer held is given back, so it can be used once by the same exact action. Anything else: state unchanged."""
    gate = _gate(table, state)
    if rec.get("outcome") == "pass" and rec.get("opening") == "once":
        args = dict(rec["args"])
        gate.form(rec["door"], args)
        key = _key(rec["door"], args)
        if key in gate.held:
            gate.openers[key] = gate.held.pop(key)
            gate.one_shot.append(key)
    return _state(gate)


def open_once(table, door, args, by, view, state=None):
    """A person opens one exact action, once: (None when opened, else the fixed reason; the gate's state)."""
    gate = _gate(table, state)
    args = dict(args)
    why = gate.form(door, args)
    if why is None:
        guard = Guarded(view)
        why = gate.open_once(door, args, by=by, view=guard)
        if guard.down:
            return DOWN, _state(_gate(table, state))
    return why, _state(gate)
