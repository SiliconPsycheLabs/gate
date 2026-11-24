"""The client of the gate's action manager: decide, ran, release. Standard library only.

Settings, each also a keyword of `Gate(...)`:
  GATE_URL      https://splabs.io (default)
  GATE_TOKEN    the account's key for agents (a `psa_gate_...` key from the console)
  GATE_TABLE    the rules table the agent works under
  GATE_SESSION  one name for every action of one task (default: one per process)
  GATE_AGENT    the agent's name, as it appears on the tape
If the gate cannot be reached the action does not pass (`fail_closed=True`, the default): an agent never acts
without an answer.
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

BASE = "/api/gate/table/v1/manager"


class GateUnreachable(RuntimeError):
    pass


@dataclass
class Decision:
    passes: bool
    reason: str = ""
    rule: str = ""
    ref: str = ""
    raw: dict = field(default_factory=dict)

    def message(self) -> str:
        """What the agent reads when the action does not pass."""
        return f"DENIED by the gate (rule {self.rule}): {self.reason}" if not self.passes else ""


def _urllib_transport(url: str, token: str, timeout: float):
    ctx = ssl.create_default_context()

    def send(path: str, body: dict) -> tuple[int, Any]:
        req = urllib.request.Request(url.rstrip("/") + path, json.dumps(body).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                              "User-Agent": "splabs-gate-sdk"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, json.loads(r.read().decode() or "null")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw
        except (urllib.error.URLError, OSError) as e:
            raise GateUnreachable(str(e)) from None
    return send


class Gate:
    def __init__(self, table: Optional[str] = None, session: Optional[str] = None, agent: Optional[str] = None,
                 url: Optional[str] = None, token: Optional[str] = None, timeout: float = 10.0,
                 fail_closed: bool = True, transport: Optional[Callable[[str, dict], tuple[int, Any]]] = None):
        self.table = table or os.environ.get("GATE_TABLE", "")
        if not self.table:
            raise ValueError("name the rules table: Gate(table=...) or GATE_TABLE")
        self.session = session or os.environ.get("GATE_SESSION") or f"s-{uuid.uuid4().hex[:12]}"
        self.agent = agent or os.environ.get("GATE_AGENT", "agent")
        self.fail_closed = fail_closed
        self._send = transport or _urllib_transport(url or os.environ.get("GATE_URL", "https://splabs.io"),
                                                    token or os.environ.get("GATE_TOKEN", ""), timeout)

    def decide(self, tool: str, args: dict) -> Decision:
        """One action, before it runs."""
        body = {"table": self.table, "session": self.session, "agent": self.agent, "tool": tool, "args": args or {}}
        try:
            status, r = self._send(f"{BASE}/decide", body)
        except GateUnreachable as e:
            if self.fail_closed:
                return Decision(False, f"the gate could not be reached ({e}), so the action was not checked", "unreachable")
            raise
        if status != 200 or not isinstance(r, dict):
            detail = r.get("detail") if isinstance(r, dict) else r
            return Decision(False, f"the gate refused the request (HTTP {status}): {detail}", "request")
        return Decision(bool(r.get("passes")), r.get("reason", ""), r.get("rule", ""), r.get("ref", ""), r)

    def ran(self, d: Decision, result: Optional[str] = None) -> None:
        """The passed action ran. Best effort: the decision is already on the tape."""
        if d.passes and d.ref:
            try:
                self._send(f"{BASE}/ran", {"session": self.session, "ref": d.ref,
                                           **({"result": result[:4000]} if isinstance(result, str) else {})})
            except GateUnreachable:
                pass

    def release(self, d: Decision) -> None:
        """The passed action did not run (an error, the agent gave up)."""
        if d.passes and d.ref:
            try:
                self._send(f"{BASE}/release", {"session": self.session, "ref": d.ref})
            except GateUnreachable:
                pass
