"""An MCP enforcement point: a stdio proxy between an agent and one MCP server (PSA prior-art review, after Watchlight's
MCP enforcement point that forwards a tool call only after the decision).

    gate mcp-proxy --server-name crm --pack coding --config owner.json --task "update Anna's phone number" \\
        -- python crm_server.py

The agent's MCP client starts this command instead of the server. Every `tools/call` is checked by the gate before it
reaches the server: allowed calls are forwarded, refused and held calls get an MCP tool error carrying the gate's fixed
reply and never reach the server. A call the gate cannot check (a parse error, an engine error) is refused: the proxy
fails closed. `tools/list` results are reported to the session (so a tool that changes its definition is seen), tool
results are reported as tool outputs (so values taken from them carry their provenance), and the task text given with
`--task` is the session's user message. Every other message passes unchanged in both directions.

Held calls are not run: the stdio channel has no person to ask. A deployment that wants approvals routes the session to
the gate service, or lists approved values in the task contract (`contract` in the owner configuration).
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading

from .. import Config, Gate, PolicySet, pack_paths
from ..checker import ALLOW


class McpProxy:
    def __init__(self, gate: Gate, server_name: str, task: str = "", agent: str = "agent", session_id: str = ""):
        self.gate = gate
        self.server = server_name
        self.session = gate.new_session()
        if task:
            self.session.observe_user(task)
        self.agent = agent
        self.session_id = session_id or f"mcp-{server_name}"
        self._pending: dict = {}             # request id -> "tools/list" or ("tools/call", tool name)
        self._lock = threading.Lock()
        self.decisions = {"allow": 0, "deny": 0, "confirm": 0, "error": 0}

    # ---- client -> server --------------------------------------------------------------------------------------

    def from_client(self, line: str) -> tuple[list[str], list[str]]:
        """One line from the client. Returns (lines to send to the server, lines to answer the client with)."""
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return [], []                    # not JSON-RPC: dropped, never forwarded
        msgs = msg if isinstance(msg, list) else [msg]
        to_server, to_client = [], []
        for m in msgs:
            if not isinstance(m, dict):
                continue
            if m.get("method") == "tools/call":
                reply = self._check_call(m)
                if reply is None:
                    to_server.append(json.dumps(m))
                else:
                    to_client.append(json.dumps(reply))
                continue
            if m.get("method") == "tools/list" and "id" in m:
                with self._lock:
                    self._pending[m["id"]] = "tools/list"
            to_server.append(json.dumps(m))
        return to_server, to_client

    def _check_call(self, m: dict) -> dict | None:
        params = m.get("params") or {}
        name = params.get("name")
        rid = m.get("id")
        action = {"type": "tool", "name": f"mcp__{self.server}__{name}", "arguments": params.get("arguments") or {}}
        try:
            if not isinstance(name, str) or not name:
                raise ValueError("tools/call without a tool name")
            d = self.gate.check(action, session=self.session, agent=self.agent, session_id=self.session_id)
        except Exception as e:  # the gate could not decide: refuse
            self.decisions["error"] += 1
            return self._error(rid, f"DENIED by the gate: the call could not be checked ({type(e).__name__}).")
        self.decisions[d.outcome] = self.decisions.get(d.outcome, 0) + 1
        if d.outcome == ALLOW:
            with self._lock:
                self._pending[rid] = ("tools/call", action["name"])
            return None
        return self._error(rid, d.reply)

    @staticmethod
    def _error(rid, text: str) -> dict:
        return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": text}], "isError": True}}

    # ---- server -> client --------------------------------------------------------------------------------------

    def from_server(self, line: str) -> str:
        """One line from the server: reported to the session when it answers a tools/list or a tools/call, then
        forwarded unchanged."""
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return line
        for m in (msg if isinstance(msg, list) else [msg]):
            if not isinstance(m, dict) or "id" not in m or ("result" not in m and "error" not in m):
                continue
            with self._lock:
                kind = self._pending.pop(m["id"], None)
            if kind == "tools/list" and isinstance(m.get("result"), dict):
                self.session.observe_tools(m["result"].get("tools", []), server=self.server)
            elif isinstance(kind, tuple):
                self.session.observe_tool_output(f"{kind[1]}:{m['id']}", _result_text(m))
        return line


def _result_text(m: dict) -> str:
    if "error" in m:
        return json.dumps(m["error"])
    res = m.get("result") or {}
    parts = []
    for c in res.get("content") or []:
        if isinstance(c, dict):
            parts.append(c.get("text") or json.dumps(c))
    if res.get("structuredContent") is not None:
        parts.append(json.dumps(res["structuredContent"]))
    return "\n".join(parts) if parts else json.dumps(res)


def run(proxy: McpProxy, command: list[str], stdin=None, stdout=None) -> int:
    """Start the server and relay both directions until the client closes its side."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    srv = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    out_lock = threading.Lock()

    def to_client(line: str) -> None:
        with out_lock:
            stdout.write(line.rstrip("\n") + "\n")
            stdout.flush()

    def pump_server() -> None:
        for line in srv.stdout:
            if line.strip():
                to_client(proxy.from_server(line.rstrip("\n")))

    t = threading.Thread(target=pump_server, daemon=True)
    t.start()
    try:
        for line in stdin:
            if not line.strip():
                continue
            to_server, answers = proxy.from_client(line.rstrip("\n"))
            for a in answers:
                to_client(a)
            for s in to_server:
                srv.stdin.write(s + "\n")
                srv.stdin.flush()
    finally:
        try:
            srv.stdin.close()
        except OSError:
            pass
        srv.wait(timeout=10)
        t.join(timeout=5)
    return srv.returncode or 0


def main(args) -> int:
    cfg = Config.load(args.config) if args.config else Config()
    paths = pack_paths(args.pack) if args.pack else []
    paths += list(args.policies or [])
    if not paths:
        sys.stderr.write("gate mcp-proxy: no rules: pass --pack and/or --policies\n")
        return 2
    g = Gate(PolicySet.from_paths(paths), cfg, log_path=args.log or None)
    task = args.task or (open(args.task_file).read() if args.task_file else "")
    proxy = McpProxy(g, args.server_name, task=task, agent=args.agent)
    return run(proxy, args.command)
