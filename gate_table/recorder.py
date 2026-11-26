"""One decision as a log record: form, decide, answer with the fixed reason, and what was read to decide.

`RecordingGate` is the engine (`engine.Gate`, unchanged) with a record around each decision. The record holds
everything needed to ask the same question again later with another table: the action as asked, what the gate read
from the company's system (the state of a record, a membership in a list, the clock, a row count), and the gate's
own small state before deciding (the openings: the gate keeps no memory of a session). It also names the rule that
decided, read from the table: the door, the condition of the door that failed, or the container that is closed.

    gate = RecordingGate(table, readers, matchers)
    rec = gate.ask(door, args, view)          # rec["outcome"]: "pass" or "nopass"; rec["reason"]: the fixed reason
    gate.ran(rec, view, result=None)          # the action ran: a one-shot opening is spent, what was read is added

    RecordedView(rec["reads"]["before"])      # answers the engine from a record; `.missing` says a read was not there
    restore(gate, rec["gate_state"])          # puts a gate in the state it had before that decision
    again(table, door, args, reads, state)    # the same action asked of another table: (reason or None, missing)

Deterministic: the same table, state, action and reads give the same record. No model, no score.
"""
import json

from .engine import Gate
from .shape import action_text, form_text, primary, shape_key, shape_of, _pattern_of

_ALL_MAX = 64_000          # a whole collection read by an expression is kept up to this many characters of JSON


def _plain(x):
    return json.loads(json.dumps(x, default=str))


def _k(x):
    return json.dumps(x, sort_keys=True, default=str)


class _Listed:
    """A list of the owner's, as the engine uses it: only "is this value in it". Each question is recorded."""

    def __init__(self, items, log):
        self.items, self.log = items, log

    def __contains__(self, x):
        ok = x in self.items
        self.log[_k(x)] = ok
        return ok


class _Reads:
    """The view of the company's system, with every answer written down."""

    def __init__(self, view):
        self.v, self.log = view, {}

    def record(self, kind, key):
        r = self.v.record(kind, key)
        self.log.setdefault("record", {}).setdefault(kind, {})[_k(key)] = _plain(r)
        return r

    def all(self, kind):
        r = self.v.all(kind)
        text = json.dumps(r, default=str)
        self.log.setdefault("all", {})[kind] = json.loads(text) if len(text) <= _ALL_MAX else {"$omitted": len(text)}
        return r

    def listed(self, name):
        return _Listed(self.v.listed(name), self.log.setdefault("listed", {}).setdefault(name, {}))

    def count(self, language, part):
        n = self.v.count(language, part)
        self.log.setdefault("count", {})[_k([language, part])] = n
        return n

    def schema(self, language):
        return self.v.schema(language)      # not written down: what the reader made of it (the operations) is

    def compiles(self, language, text):
        ok = bool(self.v.compiles(language, text))
        self.log.setdefault("compiles", {})[_k([language, text])] = ok
        return ok

    def actor(self):
        self.log["actor"] = self.v.actor()
        return self.log["actor"]

    def clock(self):
        self.log["clock"] = self.v.clock()
        return self.log["clock"]

    def day(self):
        self.log["day"] = self.v.day()
        return self.log["day"]

    def session(self):
        ask = getattr(self.v, "session", None)
        got = (ask() if ask is not None else None) or {}
        if got:
            self.log["session"] = _plain(got)
        return got

    def transaction(self, language):
        ask = getattr(self.v, "transaction", None)
        got = bool(ask(language)) if ask is not None else False
        self.log.setdefault("transaction", {})[language] = got
        return got


class RecordedView:
    """What a record says the gate read. A question the record does not answer sets `missing`: the row cannot be
    tried again with a rule that reads something the old decision did not read."""

    def __init__(self, reads):
        self.r, self.missing = reads or {}, []

    def _miss(self, what, default):
        self.missing.append(what)
        return default

    def record(self, kind, key):
        got = self.r.get("record", {}).get(kind, {})
        return got[_k(key)] if _k(key) in got else self._miss(f"record {kind}", None)

    def all(self, kind):
        got = self.r.get("all", {})
        return got[kind] if kind in got and "$omitted" not in (got[kind] or {}) else self._miss(f"all {kind}", {})

    def listed(self, name):
        view, got = self, self.r.get("listed", {}).get(name, {})

        class _In:
            def __contains__(self, x):
                return got[_k(x)] if _k(x) in got else view._miss(f"list {name}", False)
        return _In()

    def count(self, language, part):
        got = self.r.get("count", {})
        return got[_k([language, part])] if _k([language, part]) in got else self._miss("count", 10 ** 12)

    def schema(self, language):
        return {}                           # a record is asked again from the operations it holds, not from the schema

    def compiles(self, language, text):
        got = self.r.get("compiles", {})
        return got[_k([language, text])] if _k([language, text]) in got else self._miss("compiles", False)

    def actor(self):
        return self.r["actor"] if "actor" in self.r else self._miss("actor", None)

    def clock(self):
        return self.r["clock"] if "clock" in self.r else self._miss("clock", "")

    def day(self):
        return self.r["day"] if "day" in self.r else self._miss("day", None)

    def session(self):
        return self.r.get("session") or {}          # the conversation's record as the company sent it; none sent is none kept

    def transaction(self, language):
        got = self.r.get("transaction", {})
        return bool(got[language]) if isinstance(got, dict) and language in got else self._miss("transaction", False)


class SentView(RecordedView):
    """The objects the company's side sent with an action (decision of 2026-11-23: the gate reaches into no system and
    decides on what it receives). What the rules read and was not sent is kept twice: in `missing`, in words, and in
    `wanted`, as the question itself (`["count", "sql", "SELECT COUNT(*) ..."]`), so that a sender that runs none of
    our code can answer it and ask again. Answers come back in `objects.answers`, each beside its question:
    `[{"q": ["count", "sql", "SELECT COUNT(*) ..."], "a": 3}]`. The forms the recorder keeps (`record`, `count`,
    `compiles`, `actor`, `clock`, `day`, `session`, `transaction`, `all`, `listed`) are read as before, and a record is
    found under its key as the sender wrote it ("102"), whatever type the agent gave the same value."""

    def __init__(self, objects):
        super().__init__(objects if isinstance(objects, dict) else {})
        self.wanted, self.answers = [], {}
        for item in self.r.get("answers") or []:
            if isinstance(item, dict) and isinstance(item.get("q"), list):
                self.answers[_k(item["q"])] = item.get("a")

    def _ask(self, q, label, default):
        if _k(q) in self.answers:
            return self.answers[_k(q)]
        if q not in self.wanted:
            self.wanted.append(q)
        return self._miss(label, default)

    def record(self, kind, key):
        got = self.r.get("record", {}).get(kind, {})
        if isinstance(got, dict):
            for k in (_k(key), str(key)):
                if k in got:
                    return got[k]
        if key is None:                     # a record named by no key is no record: nothing a sender could be asked for
            return None                     # (the record that would name it was not sent either, and that one is asked)
        return self._ask(["record", kind, key], f"record {kind} {key}", None)

    def all(self, kind):
        got = self.r.get("all", {})
        if isinstance(got, dict) and kind in got and "$omitted" not in (got[kind] or {}):
            return got[kind]
        return self._ask(["all", kind], f"all {kind}", {})

    def listed(self, name):
        view, got = self, self.r.get("listed", {}).get(name, {})

        class _In:
            def __contains__(self, x):
                if isinstance(got, dict) and _k(x) in got:
                    return got[_k(x)]
                return bool(view._ask(["listed", name, x], f"list {name}", False))
        return _In()

    def count(self, language, part):
        got = self.r.get("count", {})
        if isinstance(got, dict) and _k([language, part]) in got:
            return got[_k([language, part])]
        return self._ask(["count", language, part], "count", 10 ** 12)

    def schema(self, language):             # asked only by rules that read the names the system has now (`live_schema`)
        got = self.r.get("schema", {})
        if isinstance(got, dict) and language in got:
            return got[language]
        return self._ask(["schema", language], f"schema {language}", {})

    def compiles(self, language, text):
        got = self.r.get("compiles", {})
        if isinstance(got, dict) and _k([language, text]) in got:
            return got[_k([language, text])]
        return bool(self._ask(["compiles", language, text], "compiles", False))

    def actor(self):
        return self.r["actor"] if "actor" in self.r else self._ask(["actor"], "actor", None)

    def clock(self):
        return self.r["clock"] if "clock" in self.r else self._ask(["clock"], "clock", "")

    def day(self):
        return self.r["day"] if "day" in self.r else self._ask(["day"], "day", None)

    def transaction(self, language):
        got = self.r.get("transaction", {})
        if isinstance(got, dict) and language in got:
            return bool(got[language])
        return bool(self._ask(["transaction", language], "transaction", False))

    def ops(self, language, text):
        """What the company's side read of a text whose translator looks at the company's own system (the shell
        reads the disk): the operations, or `{"unread": why}`. None when it was not sent."""
        return self._ask(["ops", language, text], f"the reading of the {language} text, made on the company's side", None)


def state_of(gate):
    """The gate's own state, as JSON: only what is not empty. It is the openings and nothing else: the gate keeps
    no memory of a session (no counter, no switch, no bound value, no sum of rows, no open transaction)."""
    s = {}
    if gate.one_shot:
        s["one_shot"] = list(gate.one_shot)
    if gate.task_open:
        s["task_open"] = sorted(gate.task_open)
    return s


def restore(gate, state):
    gate.reset()
    state = state or {}
    gate.one_shot = list(state.get("one_shot", []))
    gate.task_open = set(state.get("task_open", []))
    return gate


class RecordingGate(Gate):
    def __init__(self, table, readers=None, matchers=None):
        super().__init__(table, {lang: self._reading(fn) for lang, fn in (readers or {}).items()}, matchers)
        self.openers = {}           # exact action opened once -> the role that opened it
        self._trace, self._ops, self._unread, self._failed_op, self._last = [], None, False, None, None

    # ---- the engine's own steps, watched ---------------------------------------------------------------
    def _reading(self, fn):
        def read(text, schema):
            try:
                self._ops = fn(text, schema)
            except ValueError:
                self._unread = True
                raise
            return self._ops
        return read

    def check(self, c, door, args, view):
        why = super().check(c, door, args, view)
        self._trace.append((c, why))
        return why

    def allowed(self, op, view=None, language=None, counted=None):
        why = super().allowed(op, view, language, counted)
        if why:
            self._failed_op = op
        return why

    def open_once(self, door, args, by=None, view=None):
        why = super().open_once(door, args, by, view)
        if why is None:
            self.openers[_k([door, args])] = by or "owner"
        return why

    # ---- one action ------------------------------------------------------------------------------------
    def _rule(self, door, d, why, opening):
        """The rule that decided, named from the table. A door or a condition may carry its own `rule` id."""
        if why is None:
            return "opening" if opening == "once" else (d.get("rule") or door)
        if "closed" in d and door not in self.task_open:
            return d.get("rule") or f"{door}:closed"
        if self._unread:
            return f"{door}:reader"
        failed = getattr(self, "_stop_op", self._failed_op)   # the engine names the refusal that decided
        if failed is not None:
            kind, name, _part = failed
            cs = self.t.get("containers", {})
            if isinstance(cs, dict) and isinstance(cs.get(name), dict) and cs[name].get("rule"):
                return cs[name]["rule"]
            if self.t.get("container_match"):
                name = _pattern_of(self.t, kind, name, self.matchers)
            return f"{door}:{kind}" + ("" if kind in ("statements", "commands") else f":{name}")
        stopper = getattr(self, "_stopper", None)
        decided = stopper if any(stopper is c for c, _ in self._trace) else (self._trace[-1][0] if self._trace and self._trace[-1][1] else None)
        if decided is not None:
            c = decided
            if c.get("rule"):
                return c["rule"]
            for where, conds in ((door, d.get("requires", [])), ("every_door", self.t.get("every_door", []))):
                for i, x in enumerate(conds):
                    if x is c:
                        return f"{where}#{i + 1}"
        return door

    def _read_all(self, door, d, args, view):
        """An action that did not pass stopped at its first failing condition. The others are read too, only to
        write down what they read: a draft that loosens the first can then be tried on this record."""
        keep = (self._lock, self._bound, self._cel_ctx)
        for c in list(self.t.get("every_door", [])) * (door not in self.t.get("every_door_except", [])) + d.get("requires", []):
            try:
                Gate.check(self, c, door, args, view)
            except Exception:  # noqa: BLE001  a condition that cannot be read here adds nothing to the record
                pass
        self._lock, self._bound, self._cel_ctx = keep

    def ask(self, door, args, view):
        asked = _plain(args)
        args = dict(args)
        d = self.doors.get(door)
        rec = {"door": door, "args": asked, "table": str(self.t.get("table", "")), "table_version": int(self.t.get("version", 0) or 0),
               "opening": "", "opened_by": "", "gate_state": state_of(self), "text": action_text(self.t, door, asked)}
        self._trace, self._ops, self._unread, self._failed_op, self._last = [], None, False, None, None
        reads = _Reads(view)
        if d is None:
            why, rule = "this function is not in the menu", "menu"
        else:
            why = self.form(door, args)
            rule = "form"
            if why is None:
                key = _k([door, args])
                if json.dumps([door, args], sort_keys=True) in self.one_shot:
                    rec["opening"], rec["opened_by"] = "once", self.openers.get(key, "owner")
                elif "closed" in d and door in self.task_open:
                    rec["opening"] = "task"
                why = self.decide(door, args, reads)
                rule = self._rule(door, d, why, rec["opening"])
                if why is not None:
                    rec["opening"], rec["opened_by"] = "", ""
                    self._read_all(door, d, args, reads)
                self._last = (door, args)
        shape = shape_of(self.t, door, asked, self._ops, self._unread, self.matchers)
        op, container = primary(shape, self.t)
        if self._ops is not None:
            reads.log["ops"] = sorted(([k, n, p] for k, n, p in self._ops), key=_k)
        elif self._unread:
            reads.log["unread"] = True
        rec.update({"outcome": "pass" if why is None else "nopass", "reason": why or "", "rule": rule,
                    "kind": shape["kind"], "operation": op, "container": container, "shape": shape,
                    "shape_key": shape_key(shape), "form": form_text(shape), "reads": {"before": reads.log}})
        if why is not None and self._lock:
            rec["lock"] = self._lock
        if why is not None and d is not None and self.decoy:     # the third outcome: the agent is answered with the decoy
            rec["decoy"] = self.decoy
        return rec

    def ran(self, rec, view, result=None):
        """The action ran in the company's system: a one-shot opening is spent."""
        door, args = self._last
        key = _k([door, args])
        reads = _Reads(view)
        self.passed(door, args, reads, result)
        self.openers.pop(key, None)
        if reads.log:
            rec["reads"]["after"] = reads.log
        if isinstance(result, str) and self.doors.get(door, {}).get("binds"):
            rec["result"] = result
        return rec


def matchers():
    """The matchers a table may name in `container_match` and `action_match`. Functions of two strings, no rule."""
    import re
    from .reader_redis import redis_glob
    from .reader_s3 import s3_resource, wildcard
    return {"redis_glob": redis_glob, "s3_resource": s3_resource, "wildcard": wildcard,
            "regex_prefix": lambda p, name: re.match(p, name) is not None}


def again(table, door, args, reads, state, openings=True, _cache={}):
    """Ask a recorded action again of `table`, in the state and with the reads of its record. A language door is
    read from the record (the reader's output is kept in it), so nothing of the company's system is needed.
    Returns (the fixed reason, or None when it passes; what the record did not hold, if anything)."""
    before = (reads or {}).get("before", {})

    def recorded(_text, _schema):
        if before.get("unread") or "ops" not in before:
            raise ValueError("not read when it was recorded")
        return {tuple(o) for o in before["ops"]}
    key = id(table)
    if _cache.get("key") != key:
        _cache.clear()
        _cache.update(key=key, table=table, gate=Gate(table, readers={d["language"]: recorded for d in table.get("doors", {}).values()
                                                                      if isinstance(d, dict) and d.get("language")}, matchers=matchers()))
    gate = _cache["gate"]
    gate.readers = {lang: recorded for lang in gate.readers}
    state = dict(state or {})
    if state.get("session") and "session" not in before:        # a row recorded when the gate itself kept these two:
        before = {**before, "session": state["session"]}         # they are read from the record as the company's side sends them now
    if "transaction" not in before:
        before = {**before, "transaction": {d["language"]: bool(state.get("tx")) for d in table.get("doors", {}).values()
                                            if isinstance(d, dict) and d.get("language")}}
    if not openings:
        state.pop("one_shot", None)
        state.pop("task_open", None)
    restore(gate, state)
    view = RecordedView(before)
    a = dict(args) if isinstance(args, dict) else args
    try:
        why = gate.form(door, a) or gate.decide(door, a, view)
    except Exception as e:  # noqa: BLE001  a table that cannot be read does not let the action pass
        return f"the table could not be read: {type(e).__name__}", ["table"]
    return why, view.missing
