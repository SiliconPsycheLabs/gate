"""The parametric gate: one engine, the rules are a table.

Nothing about a company is written here. A table lists the doors (the menu). A door has a form (its fields and
types) and either `closed` (a fixed reason) or `requires`: a list of conditions, all of which must hold. A
condition is one of a small fixed set of kinds; each carries the reason given when it fails. The engine reads the
state of a record from the company's system through `view` (it does not keep it), and keeps for itself only
openings. The gate keeps no memory of a session.

    gate = Gate(table)
    why = gate.decide(door, args, view)        # None: passes; a string: does not pass, with the fixed reason
    gate.passed(door, args, view)              # tell the gate the action ran (a one-shot opening is spent)

A condition can also be an expression (`"if": "expr"`) in CEL, the Common Expression Language, a standard used
for policy checks elsewhere (it has no loops of its own, no side effects, and always ends). An expression sees the
call's `args`, the records the door binds by name, the `session` values and, where the door pairs two list
arguments, `pairs`. An expression that cannot be evaluated does not pass.

Standard library only, plus `cel-python` when a table uses expressions.
"""
import json

_CEL = {}
_FIXED = {}                         # collections a table marks as fixed for the session, already as CEL values


def _cel(expr):
    if expr not in _CEL:
        import celpy
        env = celpy.Environment()
        _CEL[expr] = env.program(env.compile(expr), functions={"sum": lambda xs: celpy.celtypes.DoubleType(sum(float(x) for x in xs))})
    return _CEL[expr]



def _walk(value, segs):
    """The values a path names: `name.field`, `field[]` for each element of a list, `*` for each value of a mapping."""
    if not segs:
        yield value
        return
    s, rest = segs[0], segs[1:]
    if s == "*":
        if isinstance(value, dict):
            for v in value.values():
                yield from _walk(v, rest)
        return
    many = s.endswith("[]")
    v = value.get(s[:-2] if many else s) if isinstance(value, dict) else None
    if many:
        for x in v if isinstance(v, list) else []:
            yield from _walk(x, rest)
    elif v is not None:
        yield from _walk(v, rest)

_ABSENT = object()


def _field(args, path):
    """The text a language door reads: `*` is the whole call; `a.b` is the field `b` inside the field `a`. A field the
    call does not carry is `_ABSENT` (nothing to read); a field that is there and is not text is read as given, and
    the reader refuses what it cannot read."""
    if path == "*":
        return args
    v = args
    for seg in path.split("."):
        if not isinstance(v, dict) or seg not in v:
            return _ABSENT
        v = v[seg]
    return v


def bind_order(binds):
    """Names of a door's `bind` in an order where each comes after the bound names its path starts at (`id_from`
    `order.user_id` after `order`; `keys` `res.flights[].id` after `res`); otherwise by name. Raises ValueError on a
    circle, naming it."""
    def needs(b):
        paths = [b["id_from"]] if "id_from" in b else list(b.get("keys", [])) if "each" in b else []
        return {x.split(".")[0].split("[")[0] for x in paths} & set(binds)
    deps = {n: needs(b) if isinstance(b, dict) else set() for n, b in binds.items()}
    order, done, doing = [], set(), []

    def visit(n):
        if n in done:
            return
        if n in doing:
            circle = doing[doing.index(n):] + [n]
            raise ValueError("bound names read each other in a circle: " + " -> ".join(circle))
        doing.append(n)
        for m in sorted(deps[n]):
            visit(m)
        doing.pop()
        done.add(n)
        order.append(n)
    for n in sorted(binds):
        visit(n)
    return order


class Gate:
    def __init__(self, table, readers=None, matchers=None):
        self.matchers = matchers or {}
        self.readers = readers or {}        # one reader per language: text -> atomic operations; no rule in them
        self.t = table
        self.doors = table["doors"]
        self._bind_orders = {}
        for door in self.doors:             # a circle among bound names: the table is not read
            if isinstance(self.doors[door], dict) and self.doors[door].get("bind"):
                self.bind_order(door)
        self.reset()

    def reset(self):
        # The gate keeps no memory of a session: no
        # counter, no switch, no value bound for the session, no sum of rows, no open transaction. What a rule reads
        # is in the company's objects and comes from the view. Only the owner's openings are the gate's own.
        self.one_shot = []          # exact actions opened once by the owner
        self.task_open = set()      # doors opened for the task
        self._bound = (None, None)
        self._cel_ctx = (None, None)
        self._lock = None           # the lock of the rule that stopped the last action
        self._stopper = None        # the door, condition or container that stopped the last action
        self._decoy = None          # its decoy reply, when it has one
        self._at = None
        self._rows_now = (None, {})

    # ---- openings, by the owner only -------------------------------------------------------------------
    def open_once(self, door, args, by=None, view=None):
        """One exact action, once. With `by` (a role), the lock of the rule that stops the action must name it."""
        if by is not None:
            if self.decide(door, args, view) is None:
                return "this action passes already: nothing to open"
            may = set(self.t.get("locks", {}).get(self._lock, {}).get("open", [])) | {"owner"}
            if by not in may:
                return f"opening refused: this rule is opened by {', '.join(sorted(may))}"
        self.one_shot.append(json.dumps([door, args], sort_keys=True))
        return None

    def open_for_task(self, door):
        self.task_open.add(door)

    def end_task(self):
        self.reset()

    # ---- form ------------------------------------------------------------------------------------------
    def form(self, door, args):
        d = self.doors.get(door)
        if d is None:
            return "this function is not in the menu"
        fields = d.get("form", {})
        extra = [k for k in args if k not in fields]
        if extra:
            return "field not in the function's form: " + ", ".join(sorted(extra))
        missing = [k for k in fields if k not in args or (fields[k] != "list" and not self.t.get("empty_allowed") and str(args[k]).strip() == "")]
        if missing:
            return "missing field: " + ", ".join(missing)
        for k, typ in fields.items():
            if typ == "number":
                try:
                    args[k] = float(args[k])
                except (TypeError, ValueError):
                    return f"{k} must be a number"
            elif typ == "integer":
                if isinstance(args[k], bool) or not (isinstance(args[k], int) or str(args[k]).strip().lstrip("-").isdigit()):
                    return f"{k} must be a whole number"
                args[k] = int(args[k])
            elif typ == "object":
                if not isinstance(args[k], dict):
                    return f"{k} must be an object"
            elif typ == "list":
                if not isinstance(args[k], list):
                    return f"{k} must be a list"
            else:
                args[k] = str(args[k]).strip()
        return None

    # ---- the decision ----------------------------------------------------------------------------------
    def decide(self, door, args, view):
        """None: the action passes; a string: it does not, with the fixed reason. When the rule that stopped it carries
        a `decoy`, `self.decoy` is that text: the action still does not run and the reason is logged, but the agent is
        answered with the decoy."""
        self._stopper = None
        self._stop_op = None
        why = self._decide(door, args, view)
        self._decoy = (self._stopper or {}).get("decoy") if why is not None else None
        return why

    @property
    def decoy(self):
        return self._decoy

    def _decide(self, door, args, view):
        d = self.doors.get(door)
        if d is None:
            return "this function is not in the menu"
        self._lock = d.get("lock")
        self._stop_op = None                # the operation whose refusal decided, None when a condition decided
        self._rows_now = (None, {})
        if json.dumps([door, args], sort_keys=True) in self.one_shot:
            return None
        if "closed" in d and door not in self.task_open:
            self._stopper = d
            return d["closed"]
        # Planted values first, before any language is read: a call that carries one stops here, so the log names
        # this condition and not whatever a reader would have said about the same text.
        for c in self._every(door) + d.get("requires", []):
            if c.get("if") == "no_planted_value":
                why = self.check(c, door, args, view)
                if why:
                    self._stopper = c
                    return why
        # A language door: every atomic operation of the text must be allowed. `languages` lists several texts of one
        # call, each with the path of its field (`arguments.command`: a field inside a tool's arguments); a field the
        # call does not carry is not read. `schemas`, when the table has it, gives each language its own schema.
        langs = d.get("languages") or ([{"language": d["language"], "arg": d["arg"]}] if "language" in d else [])
        counted = {}
        # A refusal that carries a lock (a person may open the action once) does not end the reading: every other rule is
        # still read, and a refusal that carries no lock wins (2026-11-25). Otherwise an action stopped by a rule
        # nobody opens (a target outside the scope, a closed script) could be opened through another rule's lock.
        held = None
        for spec in langs:
            lang, text = spec["language"], _field(args, spec["arg"])
            if text is _ABSENT:
                continue
            if lang not in self.readers:
                self._lock, self._stop_op = None, None
                return f"no reader for {lang}: the action does not pass"
            if self.t.get("compile_check") and view is not None and not view.compiles(lang, text):
                self._lock, self._stop_op = None, None
                return "statement not understood: the system itself does not take it"
            schema = self.t.get("schemas", {}).get(lang, self.t.get("schema", {}))
            if self.t.get("live_schema") and view is not None:      # the names that exist now, read from the system itself
                schema = {**schema, **view.schema(lang), "live": True}
            try:
                ops = self.readers[lang](text, schema)
            except ValueError as e:                 # a text that is not read carries no lock, whatever was held before:
                self._lock, self._stop_op = None, None      # nobody opens an action whose text the gate cannot read
                return f"statement not understood: {e}"
            except (TypeError, AttributeError):     # a value the reader cannot read as its language: it does not pass
                self._lock, self._stop_op = None, None
                return f"statement not understood: the {lang} text is not text"
            for op in sorted(ops, key=str):
                why = self.allowed(op, view, lang, counted)
                if why:
                    if self._lock is None:
                        self._stop_op = op
                        return why
                    if held is None:
                        held = (why, self._lock, self._stopper, op)
        if langs:
            self._rows_now = (json.dumps([door, args], sort_keys=True), counted)
        self._bound = (None, None)
        self._deciding = json.dumps([door, args], sort_keys=True)
        for c in self._every(door) + d.get("requires", []):
            if c.get("if") == "no_planted_value":   # already read above
                continue
            why = self.check(c, door, args, view)
            if why:
                self._stopper = c
                if "lock" in c:                     # a condition may carry its own lock
                    self._lock = c["lock"]
                if self._lock is None:
                    self._stop_op = None
                    return why
                if held is None:
                    held = (why, self._lock, c, None)
        if held is not None:
            why, self._lock, self._stopper, self._stop_op = held
            return why
        return None

    def _every(self, door):
        """The table's `every_door` conditions, unless the door is one they skip."""
        return list(self.t.get("every_door", [])) * (door not in self.t.get("every_door_except", []))

    def allowed(self, op, view=None, language=None, counted=None):
        """One atomic operation against the containers of the table: (operation, container, part). On a refusal, the
        container that refused (when there is one) is noted as what stopped the action."""
        self._at = None
        why = self._allowed(op, view, language, counted)
        if why:
            self._stopper = self._at
        return why

    def _allowed(self, op, view=None, language=None, counted=None):
        kind, name, part = op
        if kind == "statements":            # how many statements the text holds
            return "one change per text" if self.t.get("one_statement") and name > 1 and part else None
        if self.t.get("container_match"):   # containers are patterns: the name is matched, not looked up
            return self.allowed_by_pattern(kind, name)
        if kind == "commands":              # a line that destroys something holds that one command only
            return "a command that deletes stands alone on its line" if self.t.get("one_statement") and name > 1 else None
        if kind == "transaction":           # BEGIN, COMMIT, ROLLBACK of the session's own work: open where the table says so
            if not self.t.get("transactions"):
                return "transactions are not opened or closed here"
            ask = getattr(view, "transaction", None)    # whether one is open now is a fact of the company's connection
            now = bool(ask(language)) if ask is not None else False
            state = counted.get(("transaction", None), now) if counted is not None else now
            for step in str(name).split(">"):   # the transaction statements of one text, in their order
                opening = step == "transaction"
                if opening == state:
                    return "a transaction is already open" if opening else "no transaction is open"
                state = opening
            if counted is not None:
                counted[("transaction", None)] = state
            return None
        if kind == "limit":                 # a number the reader counts (recipients of a mail): at most the table's limit
            lim = self.t.get("limits", {}).get(name)
            return None if lim is None or part <= lim else f"at most {lim} {name}, this has {part}"
        if kind == "function":              # a function the table does not list is closed, where the table lists functions
            listed = self.t.get("functions_allowed")
            return None if listed is None or name in listed else f"the function {name} is not in the table"
        c = self.t.get("containers", {}).get(name)
        if kind == "structure":
            self._lock = self.t.get("structure_lock")
            return "the structure of the database is not changed"
        if c is None:
            return f"{name} is not a declared container"
        self._lock = c.get("lock")
        self._at = c
        if kind == "destroy_dirs":
            return None if c.get("destroy_dirs", True) else f"no directory of {name} is deleted"
        if kind == "rows":                  # which rows a statement touches, against the container's row conditions
            return self.rows_allowed(name, c, part, view, language)
        if kind.endswith("_rows") or kind == "destroy_files":   # how much a change touches, counted before it runs
            per = c.get(kind + "_max")           # how much one statement may touch; nothing is summed over a session
            if per is None:
                return None
            n = part if kind == "destroy_files" else view.count(language, part)
            if n > per:
                return f"this would change {n} {'files' if kind == 'destroy_files' else 'rows'} of {name}: at most {per} at a time"
            return None
        if part is not None and part in c.get("except", []):     # a part the container closes inside an open right
            return f"{kind} is closed on {name}.{part}"
        if kind == "read":
            ok = bool(c.get("read")) if part == "" else part in c.get("read", [])
        elif kind == "update":              # a list of columns (SQL), or yes and no for the whole container (a collection)
            v = c.get("update", [])
            ok = (part in v) if isinstance(v, list) else bool(v)
        else:
            v = c.get(kind)                 # a list names the parts the right covers (the attachment types that go out)
            ok = (part in v) if isinstance(v, list) and part is not None else bool(v)
        return None if ok else f"{kind} is closed on {name}" + (f".{part}" if part else "")

    # Which row conditions apply to the rows a statement touches, by what the statement does (the rows it reads, the
    # rows it changes or deletes, the new rows it writes) and whether it reads the table's columns to do it.
    def rows_allowed(self, name, c, part, view, language):
        """`c["rows"]` holds one SQL condition per right (`read`, `update`, `update_check`, `delete`, `insert_check`);
        a right with no condition opens no row, so only a statement that touches no row passes. `part` is the reader's JSON: the right, the
        rows as a query (`None` when the reader cannot say which rows), and whether the statement reads the table.
        Every touched row must satisfy the condition: a NULL does not."""
        conds = c.get("rows")
        if conds is None:
            return None
        p = json.loads(part)
        right = p["right"]
        need = [conds.get(right) if right != "update_check" else conds.get("update_check", conds.get("update"))]
        if p.get("reads"):                  # a statement that reads the table's columns also needs the read condition
            need.append(conds.get("read"))
        need = ["false" if x is None else x for x in need]   # no condition: no row is open (a statement touching none passes)
        if p.get("rows") is None:
            return f"the rows of {name} this statement touches are not read"
        pred = " AND ".join(f"COALESCE(({x}), false)" for x in need)
        try:
            n = view.count(language, f"SELECT count(*) FROM ({p['rows']}) AS gate_rows WHERE NOT ({pred})")
        except Exception as e:  # noqa: BLE001  a probe the database does not take: the statement does not pass
            return f"the rows of {name} this statement touches could not be read: {type(e).__name__}"
        what = {"read": "read", "update": "change", "delete": "delete", "update_check": "leave", "insert_check": "write"}[right]
        return f"this would {what} {n} row{'s' if n != 1 else ''} of {name} the rules do not open" if n else None

    def allowed_by_pattern(self, kind, name):
        match = self.matchers[self.t["container_match"]]
        if kind == "command":
            self._lock = self.t.get("command_locks", {}).get(name)
            return None if name in self.t.get("commands_allowed", ()) else f"the command {name} is not allowed"
        self._lock = None
        if kind == "channel":
            return None if any(match(p, name) for p in self.t.get("channels", ())) else f"the channel {name} is not allowed"
        if kind == "channel_pattern":
            ok = name in self.t.get("channels", ()) or "*" in self.t.get("channels", ())   # listed as it is, or every channel is
            return None if ok else f"the channel pattern {name} is not allowed"
        if self.t.get("container_rule") == "deny_wins":     # statements: a deny that applies wins, then any allow
            act = self.matchers[self.t["action_match"]]
            allowed = False
            for c in self.t.get("containers", []):
                on = (not any(act(p, kind) for p in c["not_actions"])) if "not_actions" in c else any(act(p, kind) for p in c["actions"])
                if not (on and any(match(p, name) for p in c["resources"])):
                    continue
                if c.get("deny"):
                    self._lock = c.get("lock")
                    self._at = c
                    return f"{kind} is denied on {name}"
                allowed = True
            self._lock = self.t.get("action_locks", {}).get(kind)
            return None if allowed else f"{kind} is closed on {name}"
        if self.t.get("container_rule") == "last":          # sudoers: the last container that matches decides
            verdict = f"{kind} is closed on {name}"
            self._lock = None
            for c in self.t.get("containers", []):
                if match(c["match"], name):
                    verdict = f"{kind} is denied on {name}" if c.get("deny") else None
                    self._lock = c.get("lock")
                    self._at = c
            if verdict is not None and self._lock is None:
                self._lock = self.t.get("default_lock")
            return verdict
        if self.t.get("container_rule") == "first":         # containers read in order: the first that matches and speaks decides
            for c in self.t.get("containers", []):
                if not match(c["match"], name):
                    continue
                self._lock = c.get("lock")
                self._at = c
                if c.get("deny"):
                    return f"{kind} is denied on {name}"
                if c.get(kind):
                    return None
            self._lock = None
            self._at = None                 # closed because nothing spoke: no container's decoy applies
            return f"{kind} is closed on {name}"
        need = [] if kind == "any" else kind.split("+")     # one container must give every right the operation needs
        for pattern, c in self.t.get("containers", {}).items():
            if (all(c.get(k) for k in need) if need else (c.get("read") or c.get("write"))) and match(pattern, name):
                return None
        return f"{kind} is closed on {name}"

    def in_cel(self, door, args, view):
        """The bound names as CEL values, built once per call; a collection the table marks `fixed` is built once."""
        ctx = self.bound(door, args, view)
        if self._cel_ctx[0] is not ctx:
            import celpy
            fixed = {n for n, b in self.doors[door].get("bind", {}).items() if b.get("fixed")}
            out = {}
            for name, value in ctx.items():
                if name in fixed:
                    if (name, id(value)) not in _FIXED:
                        _FIXED[(name, id(value))] = (value, celpy.json_to_cel(value))
                    out[name] = _FIXED[(name, id(value))][1]
                else:
                    out[name] = celpy.json_to_cel(value)
            self._cel_ctx = (ctx, out)
        return self._cel_ctx[1]

    def bind_order(self, door):
        """The door's bound names in the order they can be read, whatever order the table writes them in: a name whose
        `id_from` or `keys` path starts at another bound name is read after it. A circle is a table that is not read."""
        if door in self._bind_orders:
            return self._bind_orders[door]
        order = bind_order(self.doors[door].get("bind", {}))
        self._bind_orders[door] = order
        return order

    def bound(self, door, args, view):
        """The names an expression may use: args, session, the records the door binds, pairs."""
        key = json.dumps([door, args], sort_keys=True, default=str)
        if self._bound[0] == key:
            return self._bound[1]
        d = self.doors[door]
        try:                                    # the conversation's own record, kept and sent by the company's side;
            ask = getattr(view, "session", None)    # a view that cannot answer (no connector) gives an empty one, so an
            sess = ask() if ask is not None else None   # expression that reads it fails and one that does not is read
        except Exception:  # noqa: BLE001
            sess = None
        ctx = {"args": args, "session": dict(sess or {})}
        binds = d.get("bind", {})
        for name in self.bind_order(door):
            b = binds[name]
            if "all" in b:
                ctx[name] = view.all(b["all"])
                continue
            if "each" in b:                 # only the entries the action names: one view.record per key, absent ones left out
                ctx[name] = {}
                for path in b["keys"]:
                    for k in _walk(ctx, path.split(".")):
                        if isinstance(k, (str, int)) and not isinstance(k, bool) and k not in ctx[name]:
                            r = view.record(b["each"], k)
                            if r is not None:
                                ctx[name][k] = r
                continue
            if "id" in b:
                rid = args.get(b["id"])
            else:
                src, field = b["id_from"].split(".")
                rid = (ctx.get(src) or {}).get(field)
            ctx[name] = view.record(b["record"], rid)
        z = d.get("pairs")
        if z:
            a, b = args.get(z["a"]) or [], args.get(z["b"]) or []
            ctx["pairs"] = [{"a": x, "b": y} for x, y in zip(a, b)]
        self._bound = (key, ctx)
        return ctx

    def passed(self, door, args, view, result=None):
        """The action ran. The only thing of the gate's own that moves is a one-shot opening, which is spent."""
        key = json.dumps([door, args], sort_keys=True)
        if key in self.one_shot:
            self.one_shot.remove(key)
        self._rows_now = (None, {})

    # ---- conditions: the whole vocabulary --------------------------------------------------------------
    def check(self, c, door, args, view):
        kind = c["if"]
        if kind == "expr":
            import celpy
            try:
                ok = bool(_cel(c["expr"]).evaluate(self.in_cel(door, args, view)))
            except Exception:  # noqa: BLE001  an expression that cannot be evaluated does not pass
                ok = False
            return None if ok else c["else"].format(**{k: v for k, v in args.items() if isinstance(v, (str, int, float))})
        rec = None
        if "record" in c:
            rec = view.record(c["record"], args.get(c["id"]))
        sf = self.t.get("state_field", "state")
        ctx = {**{k: v for k, v in args.items()}, "id": args.get(c.get("id", "")), "state": (rec or {}).get(sf)}

        def no():
            return c["else"].format(**ctx)

        if kind == "record_exists":
            return None if rec is not None else no()
        if kind == "state_in":
            return None if rec is not None and rec.get(sf) in c["states"] else no()
        if kind == "arg_ends_with":
            v = str(args.get(c["arg"], ""))
            return None if (v.lower() if c.get("ignore_case") else v).endswith(c["value"]) else no()
        if kind == "arg_in_list":
            return None if args.get(c["arg"]) in view.listed(c["list"]) else no()
        if kind == "arg_max":
            return None if float(args.get(c["arg"], 0)) <= c["max"] else no()
        if kind == "record_field_max":
            return None if rec is not None and float(rec.get(c["field"], 0)) <= c["max"] else no()
        if kind == "linked_state_in":           # a second record, found through a field of the first
            other = view.record(c["linked"], (rec or {}).get(c["through"]))
            return None if other is not None and other.get("state") in c["states"] else no()
        if kind == "address_allowed":           # network: the address and port must fall in one allowed range
            import ipaddress
            try:
                ip, port = ipaddress.ip_address(str(args.get(c["address"]))), int(float(args.get(c["port"])))
            except (TypeError, ValueError):
                return no()
            for rule in self.t.get("network", {}).get("allow", []):
                if ip in ipaddress.ip_network(rule["cidr"]) and any(lo <= port <= hi for lo, hi in rule["ports"]):
                    return None
            return no()
        if kind == "time_between":
            return None if c["from"] <= view.clock() < c["to"] else no()
        if kind == "actor_not_field":            # separation of duties: whoever did the earlier step cannot do this one
            return None if rec is not None and rec.get(c["field"]) != view.actor() else no()
        if kind == "no_planted_value":           # canaries: values the owner planted that honest work never uses
            values = c.get("values")
            if not isinstance(values, list) or not values or not all(isinstance(v, str) and len(v) >= PLANTED_MIN for v in values):
                return f"the planted values of this rule are not usable: each is a text of at least {PLANTED_MIN} characters"
            texts = planted_texts(args)
            return no() if any(v in t for v in values for t in texts) else None
        raise ValueError(f"unknown condition kind {kind!r}")


PLANTED_MIN = 8     # a shorter planted value would match ordinary text by chance


def planted_texts(args):
    """Every text of a call, at any depth (values and the names of fields), each also URL-decoded: a planted value is
    searched in these as an exact substring. Numbers and booleans are not texts."""
    from urllib.parse import unquote
    out, stack = set(), [args]
    while stack:
        v = stack.pop()
        if isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
        elif isinstance(v, str):
            out.add(v)
            out.add(unquote(v))
    return out


def noted(table, door, result, session=None):
    """For the company's side, not for the gate: the conversation's record after `door` returned `result`. A door's
    `binds` says which value the company notes for the conversation (who it is for); the company keeps that record and
    sends it with each action, and the gate reads it as `session` in an expression. `once`: the first value stays."""
    session = dict(session or {})
    for name, b in (table.get("doors", {}).get(door, {}) or {}).get("binds", {}).items():
        if b.get("once") and name in session:
            continue
        if isinstance(result, str) and not result.startswith(b.get("unless_prefix", "\x00")):
            session[name] = result
    return session
