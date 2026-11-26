"""The company's sender: an action goes to the gate with the objects it is about, and actions on the same object go
one after the other. Standard library only.

The gate keeps no memory and reaches into no system: it decides on what it receives. So an action and the objects it
is judged on must stay together until the action ran. If two actions on the same record are asked at the same
instant, both are judged on the record as it was, and both can pass (the third payment of a day that allows three,
asked twice). This sender keeps the order for you: every record the gate reads for an action is held from the ask
until the action ran or did not, and the second action is judged on the record as the first left it. Actions that
share no record go together.

    from splabs_gate.sender import Sender

    def read(q):                                    # your own reader: one question of the gate, one answer
        if q[0] == "record":                        # ["record", "invoice", "88"]
            return erp.get(q[1], q[2])              # the record, or None when there is none
        if q[0] == "clock":
            return time.strftime("%H:%M")
        raise KeyError(q)                           # a question you do not answer: the action does not pass

    sender = Sender(table="payments", read=read)
    out = sender.act("pay_invoice", {"number": "88"}, do=lambda: erp.pay("88"), session="ticket-4711", agent="payments-bot")
    if not out.passes:
        tell_the_agent(out.message())

Settings, each also a keyword of `Sender(...)`:
  GATE_URL            https://splabs.io (default)
  GATE_SENDER_TOKEN   the account's key for the company's side (a `psa_send_...` key from the console)
  GATE_TABLE          the rules table

Where the order is kept (`locks=`), by where your senders run:
  LocalLocks()                 threads of one process (the default)
  FileLocks("/var/lock/gate")  processes of one machine
  PostgresLocks(connect)       several machines: advisory locks on a PostgreSQL you already run; `connect` returns a
                               new DB-API connection (psycopg, pg8000, ...)
  NoOrder()                    no order kept here: your own system keeps it (it refuses at execution a move from a
                               state the object is no longer in)

What is held (`order=`): "records" (the default) holds each record the gate reads, alone, and a whole kind when the
gate reads all of it; "table" lets one action at a time through for the rules table; or a function
`(tool, args, questions) -> names` of your own. The record an action moves by the table is held too: the gate names it
in its answer (`moves`). Any other record your function changes, that neither a rule reads nor the table names, is
held when you name it: `act(..., touches=[("supplier", "S1")])`.

If the gate cannot be reached, a reader fails, or the records stay held by other actions past `wait` seconds, the
action does not pass and `do` is not called.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from .client import BASE, GateUnreachable, _urllib_transport

NOT_SENT = "not_sent"


class Busy(RuntimeError):
    """The records an action needs stayed held by other actions past the wait."""


def _k(v) -> str:
    return json.dumps(v, sort_keys=True, default=str)


# ---- where the order is kept ----------------------------------------------------------------------------------
class NoOrder:
    """Holds nothing: the company's own system keeps the order."""

    @contextlib.contextmanager
    def hold(self, names, wait=60.0):
        yield


class _ReadWrite:
    """Many readers or one writer, for threads of one process."""

    def __init__(self):
        self.cond, self.readers, self.writer, self.users = threading.Condition(), 0, False, 0

    def take(self, write, deadline):
        with self.cond:
            while self.writer or (write and self.readers):
                left = deadline - time.monotonic()
                if left <= 0 or not self.cond.wait(left):
                    if self.writer or (write and self.readers):
                        return False
            if write:
                self.writer = True
            else:
                self.readers += 1
            return True

    def give(self, write):
        with self.cond:
            if write:
                self.writer = False
            else:
                self.readers -= 1
            self.cond.notify_all()


class LocalLocks:
    """The order among the threads of one process."""

    def __init__(self):
        self._guard, self._locks = threading.Lock(), {}

    @contextlib.contextmanager
    def hold(self, names, wait=60.0):
        deadline, taken = time.monotonic() + wait, []
        try:
            for name, write in names:
                with self._guard:
                    lock = self._locks.setdefault(name, _ReadWrite())
                    lock.users += 1
                if not lock.take(write, deadline):
                    with self._guard:
                        lock.users -= 1
                    raise Busy(name)
                taken.append((name, lock, write))
            yield
        finally:
            for name, lock, write in reversed(taken):
                lock.give(write)
                with self._guard:
                    lock.users -= 1
                    if not lock.users:
                        self._locks.pop(name, None)


class FileLocks:
    """The order among the processes of one machine: one lock file per name under `directory` (POSIX)."""

    def __init__(self, directory):
        self.directory = str(directory)
        os.makedirs(self.directory, exist_ok=True)

    @contextlib.contextmanager
    def hold(self, names, wait=60.0):
        import fcntl
        deadline, taken = time.monotonic() + wait, []
        try:
            for name, write in names:
                fd = os.open(os.path.join(self.directory, hashlib.sha256(name.encode()).hexdigest()[:40] + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
                taken.append(fd)
                mode = (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB
                while True:
                    try:
                        fcntl.flock(fd, mode)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise Busy(name) from None
                        time.sleep(0.005)
            yield
        finally:
            for fd in reversed(taken):
                os.close(fd)                            # closing the file gives the lock back


class PostgresLocks:
    """The order among several machines: session advisory locks on a PostgreSQL the company already runs. `connect`
    returns a new DB-API connection each time it is called; one connection is used per action and closed after it,
    which gives its locks back even if the sender dies. `scope` keeps two uses of one database apart."""

    def __init__(self, connect: Callable[[], Any], scope: str = "splabs-gate", placeholder: str = "%s"):
        self.connect, self.scope, self.ph = connect, scope, placeholder

    def _number(self, name) -> int:
        return int.from_bytes(hashlib.sha256(f"{self.scope}\0{name}".encode()).digest()[:8], "big", signed=True)

    @contextlib.contextmanager
    def hold(self, names, wait=60.0):
        names = list(names)
        if not names:
            yield
            return
        deadline, con = time.monotonic() + wait, self.connect()
        try:
            cur = con.cursor()
            for name, write in names:
                fn = "pg_try_advisory_lock" if write else "pg_try_advisory_lock_shared"
                while True:
                    cur.execute(f"SELECT {fn}({self.ph})", (self._number(name),))
                    got = cur.fetchone()[0]
                    with contextlib.suppress(Exception):
                        con.commit()                    # a session lock outlives the transaction; nothing is left open
                    if got:
                        break
                    if time.monotonic() >= deadline:
                        raise Busy(name)
                    time.sleep(0.01)
            yield
        finally:
            with contextlib.suppress(Exception):
                con.close()                             # the session ends: every lock it held is given back


# ---- the sender -----------------------------------------------------------------------------------------------
@dataclass
class Outcome:
    passes: bool
    reason: str = ""
    rule: str = ""
    ref: str = ""
    result: Any = None          # what `do` returned, when the action passed and ran
    asks: int = 0               # how many times the gate was asked for this action
    waited: float = 0.0         # seconds spent waiting for records other actions held
    raw: dict = field(default_factory=dict)

    def message(self) -> str:
        """What the agent reads when the action does not pass."""
        return f"DENIED by the gate (rule {self.rule}): {self.reason}" if not self.passes else ""


def held_for(questions, order="records", table="") -> list:
    """The names to hold for the questions the gate asked, each with whether it is held alone (True) or may be shared
    (False). A record is held alone and its kind shared; a question about all of a kind holds the kind alone."""
    if order == "table":
        return [(f"table/{table}", True)]
    want = {}
    for q in questions:
        if not isinstance(q, (list, tuple)) or not q:
            continue
        if q[0] == "record" and len(q) >= 3:
            want.setdefault(f"kind/{q[1]}", False)
            want[f"record/{q[1]}/{q[2]}"] = True
        elif q[0] == "all" and len(q) >= 2:
            want[f"kind/{q[1]}"] = True
        elif q[0] == "listed" and len(q) >= 2:
            want.setdefault(f"list/{q[1]}", False)
    return sorted(want.items())


def _no_key(q) -> bool:
    """A record asked for with no key: the gate does not know yet which one (the record that names it was not sent
    either). It asks again with the key once it has that record, so this one is neither answered nor held."""
    return isinstance(q, (list, tuple)) and len(q) >= 3 and q[0] == "record" and q[2] is None


class Sender:
    def __init__(self, table: Optional[str] = None, read: Optional[Callable[[list], Any]] = None, locks=None, order="records",
                 url: Optional[str] = None, token: Optional[str] = None, timeout: float = 30.0, wait: float = 60.0, rounds: int = 8,
                 transport: Optional[Callable[[str, dict], tuple[int, Any]]] = None):
        self.table = table or os.environ.get("GATE_TABLE", "")
        if not self.table:
            raise ValueError("name the rules table: Sender(table=...) or GATE_TABLE")
        if read is None:
            raise ValueError("give the reader of your own system: Sender(read=...)")
        self.read, self.locks, self.order, self.wait, self.rounds = read, locks if locks is not None else LocalLocks(), order, wait, rounds
        self._send = transport or _urllib_transport(url or os.environ.get("GATE_URL", "https://splabs.io"),
                                                    token or os.environ.get("GATE_SENDER_TOKEN") or os.environ.get("GATE_TOKEN", ""), timeout)

    # what to hold for an action
    def _names(self, tool, args, questions, touches) -> list:
        if callable(self.order):
            names = {str(n): True for n in self.order(tool, args, questions)}
        else:
            names = dict(held_for(questions, self.order, self.table))
        for t in touches or ():                          # records the action changes without its rules reading them
            if isinstance(t, (list, tuple)) and len(t) == 2:
                names.setdefault(f"kind/{t[0]}", False)
                names[f"record/{t[0]}/{t[1]}"] = True
            else:
                names[str(t)] = True
        return sorted(names.items())

    def _answers(self, questions) -> list:
        """Each question answered by the company's reader, now. Read while the records are held."""
        return [{"q": q, "a": self.read(list(q))} for q in questions]

    def act(self, tool: str, args: dict, do: Callable[[], Any], session: Optional[str] = None, agent: str = "",
            touches: Iterable = (), first: Iterable = ()) -> Outcome:
        """One action: asked, and if it passes carried out by `do` and confirmed, with its records held all the while.
        `first` may name questions you know the rules will ask (`[["record", "invoice", "88"]]`), to save one ask."""
        session = session or f"s-{uuid.uuid4().hex[:12]}"
        body = {"table": self.table, "session": session, "agent": agent, "tool": tool, "args": args or {}}
        questions, moved, asks, waited, touches = [list(q) for q in first], [], 0, 0.0, list(touches or ())
        for _ in range(self.rounds):
            names = self._names(tool, args, questions, touches + moved)
            started = time.monotonic()
            try:
                with self.locks.hold(names, self.wait):
                    waited += time.monotonic() - started
                    again = False
                    for _ in range(self.rounds):
                        try:
                            objects = {"answers": self._answers(questions)}        # read afresh each time: the records are ours now
                        except Exception as e:  # noqa: BLE001  a reader that fails lets nothing through
                            return Outcome(False, f"the company's reader could not answer ({type(e).__name__}: {e}), so the action was not checked",
                                           "reader", asks=asks, waited=waited)
                        try:
                            status, r = self._send(f"{BASE}/action", {**body, "objects": objects})
                        except GateUnreachable as e:
                            return Outcome(False, f"the gate could not be reached ({e}), so the action was not checked", "unreachable",
                                           asks=asks, waited=waited)
                        asks += 1
                        if status != 200 or not isinstance(r, dict):
                            detail = r.get("detail") if isinstance(r, dict) else r
                            return Outcome(False, f"the gate refused the request (HTTP {status}): {detail}", "request", asks=asks, waited=waited)
                        wanted = [q for q in (r.get("wanted") or []) if q not in questions and not _no_key(q)] if r.get("rule") == NOT_SENT else []
                        questions += wanted
                        moved += [(m[1], m[2]) for m in (r.get("moves") or [])      # the record the action moves, named by the gate
                                  if isinstance(m, list) and len(m) == 3 and m[0] == "record" and m[2] is not None and (m[1], m[2]) not in moved]
                        if self._names(tool, args, questions, list(touches) + moved) != names:
                            if r.get("passes"):
                                self._release(session, r.get("ref", ""))     # that answer is not acted on: asked again with all held
                            again = True                   # more to hold: let go, take everything in one order, read afresh
                            break
                        if wanted:
                            continue
                        out = Outcome(bool(r.get("passes")), r.get("reason", ""), r.get("rule", ""), r.get("ref", ""), None, asks, waited, r)
                        if not out.passes:
                            return out
                        try:
                            out.result = do()
                        except BaseException:
                            self._release(session, out.ref)
                            raise
                        self._ran(session, out.ref, questions)
                        return out
                    if not again:
                        return Outcome(False, "the gate kept asking for more after the rounds allowed", "rounds", asks=asks, waited=waited)
            except Busy as e:
                return Outcome(False, f"other actions held what this one needs for {self.wait:g} seconds ({e}), so it was not asked",
                               "busy", asks=asks, waited=waited + (time.monotonic() - started))
        return Outcome(False, "the gate kept asking for more after the rounds allowed", "rounds", asks=asks, waited=waited)

    def _ran(self, session, ref, questions) -> None:
        """The action ran: the gate is told, with the objects as they are now. Best effort: the decision is on the tape."""
        if not ref:
            return
        with contextlib.suppress(Exception):
            self._send(f"{BASE}/ran", {"session": session, "ref": ref, "objects": {"answers": self._answers(questions)}})

    def _release(self, session, ref) -> None:
        if ref:
            with contextlib.suppress(Exception):
                self._send(f"{BASE}/release", {"session": session, "ref": ref})
