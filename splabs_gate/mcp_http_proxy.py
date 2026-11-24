"""The gate in front of a remote MCP server (Streamable HTTP transport). An MCP client is pointed at this proxy's
address instead of the server's; every message is forwarded unchanged, headers included (`Mcp-Session-Id`, auth),
except each `tools/call`, which is sent to the gate first. A call that does not pass gets, as its HTTP answer, a tool
result with `isError: true` and the gate's reason; the server never sees it.

    python -m splabs_gate.mcp_http_proxy --table T --upstream https://mcp.example.com/mcp [--port 8765] [--agent A]

The session of the gate is the MCP session (`Mcp-Session-Id`), so each client conversation is one session on the tape.
Answers the server streams (`text/event-stream`) are passed through as they come. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .client import Gate

HOP = {"host", "content-length", "connection", "transfer-encoding", "keep-alive", "accept-encoding"}


def make_handler(upstream: str, table: str, agent: str, gate_factory=None):
    gates = {}

    def gate_for(session: str) -> Gate:
        if session not in gates:
            gates[session] = (gate_factory or (lambda s: Gate(table=table, session=s, agent=agent)))(session)
        return gates[session]

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _forward(self, method: str, body: bytes | None):
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
            req = urllib.request.Request(upstream, data=body, method=method, headers=headers)
            try:
                r = urllib.request.urlopen(req, timeout=300)
            except urllib.error.HTTPError as e:
                r = e
            self.send_response(r.status if hasattr(r, "status") else r.code)
            stream = (r.headers.get("Content-Type") or "").startswith("text/event-stream")
            for k, v in r.headers.items():
                if k.lower() not in HOP:
                    self.send_header(k, v)
            if stream:
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                while True:
                    chunk = r.readline()
                    if not chunk:
                        break
                    self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
            else:
                data = r.read()
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        def _refuse(self, msg_id, text: str):
            data = json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {
                "content": [{"type": "text", "text": text}], "isError": True}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            try:
                msg = json.loads(body or b"null")
            except ValueError:
                msg = None
            if isinstance(msg, dict) and msg.get("method") == "tools/call" and "id" in msg:
                p = msg.get("params") or {}
                session = self.headers.get("Mcp-Session-Id") or "mcp-http"
                d = gate_for(session).decide(str(p.get("name", "")), {"arguments": p.get("arguments") or {}})
                if not d.passes:
                    return self._refuse(msg["id"], d.message())
            self._forward("POST", body)

        def do_GET(self):
            self._forward("GET", None)

        def do_DELETE(self):
            self._forward("DELETE", None)

    return Handler


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="splabs_gate.mcp_http_proxy")
    ap.add_argument("--table", required=True)
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--agent", default="mcp-agent")
    a = ap.parse_args(argv)
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(a.upstream, a.table, a.agent))
    print(f"gate proxy on http://{a.host}:{a.port} -> {a.upstream}", file=sys.stderr, flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
