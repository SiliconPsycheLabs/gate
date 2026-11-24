"""The gate in front of any MCP server (stdio). Every MCP client (Claude Desktop, Cursor, Windsurf, Claude Code, an
agent framework) can be pointed at this proxy instead of the server: messages pass through unchanged, except each
`tools/call`, which is sent to the gate first. If it passes it goes on to the server; if not, the client gets a tool
result with `isError: true` and the gate's reason, and the server never sees the call.

    python -m splabs_gate.mcp_proxy --table files_agent [--session S] [--agent A] -- <server command> [args...]

In an MCP client's configuration, the server's command becomes `python` with these arguments, e.g.

    {"command": "python", "args": ["-m", "splabs_gate.mcp_proxy", "--table", "files_agent", "--",
                                   "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"],
     "env": {"GATE_TOKEN": "psa_gate_..."}}

The table's tools are the server's tools, their arguments under `arguments` (the console compiles a table from the
server's `tools/list`; `python -m splabs_gate.mcp_proxy --list-tools -- <server command>` prints it). Stdio framing:
one JSON-RPC message per line.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading

from .client import Gate


def _write(stream, lock, msg) -> None:
    data = (json.dumps(msg, ensure_ascii=False) + "\n").encode()
    with lock:
        stream.write(data)
        stream.flush()


class Proxy:
    def __init__(self, gate: Gate, server_cmd: list[str], client_in=None, client_out=None):
        self.gate = gate
        self.server = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.cin = client_in or sys.stdin.buffer
        self.cout = client_out or sys.stdout.buffer
        self.out_lock, self.srv_lock = threading.Lock(), threading.Lock()
        self.waiting = {}                   # request id -> the decision of a call that went to the server

    def _from_client(self) -> None:
        for line in self.cin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                _write(self.server.stdin, self.srv_lock, line.decode(errors="replace"))
                continue
            if isinstance(msg, dict) and msg.get("method") == "tools/call" and "id" in msg:
                p = msg.get("params") or {}
                d = self.gate.decide(str(p.get("name", "")), {"arguments": p.get("arguments") or {}})
                if not d.passes:
                    _write(self.cout, self.out_lock, {"jsonrpc": "2.0", "id": msg["id"], "result": {
                        "content": [{"type": "text", "text": d.message()}], "isError": True}})
                    continue
                self.waiting[json.dumps(msg["id"])] = d
            _write(self.server.stdin, self.srv_lock, msg)
        self.server.stdin.close()

    def _from_server(self) -> None:
        for line in self.server.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                with self.out_lock:
                    self.cout.write(line)
                    self.cout.flush()
                continue
            if isinstance(msg, dict) and "id" in msg and ("result" in msg or "error" in msg):
                d = self.waiting.pop(json.dumps(msg["id"]), None)
                if d is not None:
                    failed = "error" in msg or bool((msg.get("result") or {}).get("isError"))
                    (self.gate.release(d) if failed else self.gate.ran(d))
            _write(self.cout, self.out_lock, msg)

    def run(self) -> int:
        t = threading.Thread(target=self._from_server, daemon=True)
        t.start()
        self._from_client()
        t.join()
        return self.server.wait()


def list_tools(server_cmd: list[str]) -> dict:
    """Ask the server what it declares (initialize, then tools/list) and return the answer."""
    p = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def ask(msg):
        p.stdin.write((json.dumps(msg) + "\n").encode())
        p.stdin.flush()
        while True:
            r = json.loads(p.stdout.readline())
            if r.get("id") == msg.get("id"):
                return r
    ask({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "splabs-gate", "version": "0.1"}}})
    p.stdin.write((json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode())
    p.stdin.flush()
    tools, cursor = [], None
    while True:
        r = ask({"jsonrpc": "2.0", "id": 2 + len(tools), "method": "tools/list", "params": {"cursor": cursor} if cursor else {}})
        tools += r.get("result", {}).get("tools", [])
        cursor = r.get("result", {}).get("nextCursor")
        if not cursor:
            break
    p.terminate()
    return {"tools": tools}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in argv:
        print("usage: python -m splabs_gate.mcp_proxy --table T [--session S] [--agent A] -- <server command>", file=sys.stderr)
        return 2
    i = argv.index("--")
    ap = argparse.ArgumentParser(prog="splabs_gate.mcp_proxy")
    ap.add_argument("--table")
    ap.add_argument("--session")
    ap.add_argument("--agent", default="mcp-agent")
    ap.add_argument("--list-tools", action="store_true")
    a = ap.parse_args(argv[:i])
    if a.list_tools:
        print(json.dumps(list_tools(argv[i + 1:]), indent=1))
        return 0
    return Proxy(Gate(table=a.table, session=a.session, agent=a.agent), argv[i + 1:]).run()


if __name__ == "__main__":
    sys.exit(main())
