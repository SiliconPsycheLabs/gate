"""The view: how the gate reads the company's system at the moment of a decision.

The gate keeps no copy of a company's records. When a rule needs the state of a record, it asks a view. The view is
answered by a small **connector the company runs next to its own system**; the gate holds no credential to the
company's data.

The whole contract is eight calls. A connector answers these and nothing else:

    record(kind, key)        the record as a dict (its state in the field the table names in `state_field`), or None
    all(kind)                a whole collection the table binds (a price list), as a dict of records
    listed(name)             a list of the owner's; the gate only asks "is this value in it"
    count(language, probe)   how many rows a probe matches; the probe is a read written by the reader, never a change
    compiles(language, text) whether the system itself takes the text as a statement (compiled, not run)
    schema(language)         the names that exist now: {"tables": {name: [columns]}, "views": {name: its SELECT}}
    actor()                  who is acting
    clock(), day()           the time as "HH:MM" and the day, as the company's system sees them

`Guarded` is what the manager wraps around any view: a call that fails, or that the view does not have, is written
down and answered with the value that lets nothing through; the manager then refuses the action whatever the rules
would have said. A system that does not answer never lets an action pass.
"""
import json
import sqlite3
import urllib.request

_SAFE = {"record": None, "all": {}, "count": 10 ** 12, "compiles": False, "actor": None, "clock": "", "day": None,
         "schema": {"tables": {}, "views": {}}, "session": {}, "transaction": False}


class _Nothing:
    def __contains__(self, x):
        return False


class Guarded:
    def __init__(self, view):
        self.v, self.down = view, ""

    def _ask(self, name, *args):
        try:
            return getattr(self.v, name)(*args)
        except Exception as e:  # noqa: BLE001  whatever went wrong, the answer is "did not answer"
            self.down = self.down or f"{name}: {type(e).__name__}"
            return _SAFE.get(name)

    def record(self, kind, key):
        return self._ask("record", kind, key)

    def all(self, kind):
        return self._ask("all", kind)

    def count(self, language, probe):
        return self._ask("count", language, probe)

    def compiles(self, language, text):
        return self._ask("compiles", language, text)

    def schema(self, language):
        return self._ask("schema", language)

    def actor(self):
        return self._ask("actor")

    def clock(self):
        return self._ask("clock")

    def day(self):
        return self._ask("day")

    def session(self):                      # the conversation's own record; a view that keeps none says nothing
        return (self._ask("session") or {}) if hasattr(self.v, "session") else {}

    def transaction(self, language):        # whether a transaction of the company's connection is open now
        return bool(self._ask("transaction", language)) if hasattr(self.v, "transaction") else False

    def listed(self, name):
        guard = self
        try:
            inner = self.v.listed(name)
        except Exception as e:  # noqa: BLE001
            self.down = self.down or f"listed: {type(e).__name__}"
            return _Nothing()

        class _In:
            def __contains__(self, x):
                try:
                    return x in inner
                except Exception as e:  # noqa: BLE001
                    guard.down = guard.down or f"listed: {type(e).__name__}"
                    return False
        return _In()


class HttpView:
    """A connector reached over HTTPS: POST {"call": name, "args": [...]} -> {"value": ...}. The connector is the
    company's; this client only carries the seven questions and a bearer token the company issued for it."""

    def __init__(self, url, token, timeout=3.0):
        self.url, self.token, self.timeout = url, token, timeout

    def _ask(self, call, *args):
        req = urllib.request.Request(self.url, json.dumps({"call": call, "args": list(args)}).encode(),
                                     {"Content-Type": "application/json", "Authorization": "Bearer " + self.token})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read())["value"]

    def record(self, kind, key):
        return self._ask("record", kind, key)

    def all(self, kind):
        return self._ask("all", kind)

    def count(self, language, probe):
        return int(self._ask("count", language, probe))

    def compiles(self, language, text):
        return self._ask("compiles", language, text) is True

    def schema(self, language):
        return self._ask("schema", language)

    def actor(self):
        return self._ask("actor")

    def clock(self):
        return self._ask("clock")

    def day(self):
        return self._ask("day")

    def session(self):                      # a connector that keeps no record of the conversation says nothing
        try:
            return self._ask("session") or {}
        except Exception:  # noqa: BLE001
            return {}

    def transaction(self, language):
        return bool(self._ask("transaction", language))

    def listed(self, name):
        view = self

        class _In:
            def __contains__(self, x):
                return view._ask("listed_has", name, x) is True
        return _In()


class SqliteView:
    """A reference connector on a SQLite database, as a company would write its own: which table holds each kind of
    record and under which key column, which query answers each list. Used by the tests; a model for other systems.

        SqliteView(con, records={"invoice": ("invoices", "number")}, lists={"company_domains": "SELECT d FROM domains"},
                   actor="ada", now=lambda: ("10:30", "2026-11-22"))
    """

    def __init__(self, con, records=None, lists=None, actor=None, now=None):
        self.con, self.records, self.lists, self.who, self.now = con, records or {}, lists or {}, actor, now

    def record(self, kind, key):
        table, column = self.records[kind]
        cur = self.con.execute(f"SELECT * FROM {table} WHERE {column} = ?", (key,))
        row = cur.fetchone()
        return None if row is None else dict(zip([c[0] for c in cur.description], row))

    def all(self, kind):
        table, column = self.records[kind]
        cur = self.con.execute(f"SELECT * FROM {table}")
        names = [c[0] for c in cur.description]
        return {str(r[names.index(column)]): dict(zip(names, r)) for r in cur.fetchall()}

    def listed(self, name):
        return {r[0] for r in self.con.execute(self.lists[name])}

    def count(self, language, probe):
        if not probe.lstrip().upper().startswith(("SELECT", "WITH")):
            raise ValueError("a probe is a read")
        return self.con.execute(probe).fetchone()[0]

    def schema(self, language):
        tables, views = {}, {}
        for kind, name, sql in self.con.execute("SELECT type, name, sql FROM sqlite_master WHERE type IN ('table', 'view') "
                                                "AND name NOT LIKE 'sqlite_%'").fetchall():
            if kind == "table":
                tables[name] = [r[1] for r in self.con.execute(f"PRAGMA table_info({name})")]
            else:
                views[name] = sql[sql.upper().index(" AS ") + 4:]
        return {"tables": tables, "views": views}

    def compiles(self, language, text):
        parts, buf = [], ""
        for ch in text:
            buf += ch
            if ch == ";" and sqlite3.complete_statement(buf):
                parts.append(buf)
                buf = ""
        if buf.strip():
            parts.append(buf)
        try:
            for p in parts:
                self.con.execute("EXPLAIN " + p).fetchall()
        except (sqlite3.Error, sqlite3.Warning):
            return False
        return bool(parts)

    def actor(self):
        return self.who

    def clock(self):
        return self.now()[0]

    def day(self):
        return self.now()[1]

    def session(self):
        return {}

    def transaction(self, language):
        return bool(self.con.in_transaction)
