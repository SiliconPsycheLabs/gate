"""The SDK's MCP proxy (splabs_gate): a tools/call goes to the gate first; a call that does not pass never
reaches the server and the client reads the gate's reason; a call that passes runs and is confirmed (`ran`), one that
fails on the server is given back (`release`). No network: the gate is a fake transport, the server a tiny script."""
import io
import json
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from splabs_gate import Gate  # noqa: E402
from splabs_gate.mcp_proxy import Proxy  # noqa: E402

SERVER = textwrap.dedent("""
    import json, sys
    for line in sys.stdin:
        m = json.loads(line)
        if "id" not in m:
            continue
        if m["method"] == "tools/call":
            name = m["params"]["name"]
            if name == "boom":
                print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"content": [{"type": "text", "text": "x"}], "isError": True}}), flush=True)
            else:
                open(sys.argv[1], "a").write(name + "\\n")
                print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"content": [{"type": "text", "text": "done " + name}]}}), flush=True)
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"ok": True}}), flush=True)
""")


def run(tmp_path, calls):
    server, ran_log = tmp_path / "server.py", tmp_path / "ran.txt"
    server.write_text(SERVER)
    sent = []

    def transport(path, body):
        sent.append((path, body))
        if path.endswith("/decide"):
            ok = body["tool"] != "delete_all"
            return 200, {"passes": ok, "reason": "" if ok else "delete_all is closed", "rule": "delete_all:closed" * (not ok),
                         "ref": f"r{len(sent)}"}
        return 200, {"ok": True}
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}] + [
        {"jsonrpc": "2.0", "id": i + 2, "method": "tools/call", "params": {"name": n, "arguments": a}} for i, (n, a) in enumerate(calls)]
    cin = io.BytesIO(("\n".join(json.dumps(m) for m in msgs) + "\n").encode())
    cout = io.BytesIO()
    Proxy(Gate(table="t", session="s", transport=transport), [sys.executable, str(server), str(ran_log)], cin, cout).run()
    out = {r["id"]: r for r in (json.loads(x) for x in cout.getvalue().decode().splitlines())}
    return out, sent, (ran_log.read_text().split() if ran_log.exists() else [])


def test_the_gate_decides_every_tool_call(tmp_path):
    out, sent, ran = run(tmp_path, [("read_file", {"path": "a"}), ("delete_all", {}), ("boom", {})])
    assert out[1]["result"] == {"ok": True}                                   # not a tool call: passed through
    assert out[2]["result"]["content"][0]["text"] == "done read_file"
    assert out[3]["result"]["isError"] and "delete_all is closed" in out[3]["result"]["content"][0]["text"]
    assert ran == ["read_file"]                                               # the refused call never reached the server
    decided = [b for p, b in sent if p.endswith("/decide")]
    assert [b["tool"] for b in decided] == ["read_file", "delete_all", "boom"]
    assert decided[0]["args"] == {"arguments": {"path": "a"}} and decided[0]["table"] == "t"
    assert [p.rsplit("/", 1)[1] for p, _ in sent if not p.endswith("/decide")] == ["ran", "release"]


def test_no_answer_from_the_gate_means_no_action(tmp_path):
    from splabs_gate.client import GateUnreachable

    def down(path, body):
        raise GateUnreachable("connection refused")
    d = Gate(table="t", transport=down).decide("read_file", {})
    assert not d.passes and "could not be reached" in d.reason


def test_function_calls_are_decided_before_they_run():
    from splabs_gate.openai import run_tool_calls
    decided, ran, settled = [], [], []

    def transport(path, body):
        if path.endswith("/decide"):
            decided.append(body["tool"])
            ok = "amount" in body["args"] and body["args"]["amount"] <= 100      # an unparsed call fits no form
            return 200, {"passes": ok, "reason": "" if ok else "a refund above 100 euros is decided by a person",
                         "rule": "refund#1", "ref": f"r{len(decided)}"}
        settled.append(path.rsplit("/", 1)[1])
        return 200, {"ok": True}
    msg = {"role": "assistant", "tool_calls": [
        {"id": "a", "type": "function", "function": {"name": "refund", "arguments": '{"order_id": "1", "amount": 480}'}},
        {"id": "b", "type": "function", "function": {"name": "refund", "arguments": '{"order_id": "2", "amount": 40}'}},
        {"id": "c", "type": "function", "function": {"name": "refund", "arguments": "not json"}}]}
    out = run_tool_calls(Gate(table="t", transport=transport), msg, {"refund": lambda order_id, amount: ran.append(amount) or "ok"})
    assert ran == [40]                                  # 480 never ran; the unparsed call reached no function
    assert "decided by a person" in out[0]["content"] and out[1]["content"] == "ok"
    assert [o["tool_call_id"] for o in out] == ["a", "b", "c"] and settled == ["ran"]          # only the call that passed and ran is confirmed


def test_hooks_read_each_agent_and_answer_in_its_format():
    from splabs_gate.client import Decision
    from splabs_gate.hooks import action, answer
    assert action("claude-code", {"session_id": "s", "tool_name": "Bash", "tool_input": {"command": "ls"}}) == ("s", "Bash", {"command": "ls"})
    assert action("codex", {"session_id": "s", "tool_name": "apply_patch", "tool_input": {"command": "*** Begin Patch"}}) == \
        ("s", "apply_patch", {"command": "*** Begin Patch"})
    assert action("cursor", {"conversation_id": "c", "hook_event_name": "beforeShellExecution", "command": "rm -rf /"}) == \
        ("c", "Shell", {"command": "rm -rf /"})
    assert action("cursor", {"conversation_id": "c", "hook_event_name": "beforeMCPExecution", "tool_name": "send",
                             "tool_input": '{"to": "x"}'}) == ("c", "send", {"arguments": {"to": "x"}})
    assert action("cursor", {"conversation_id": "c", "hook_event_name": "beforeReadFile", "file_path": "/etc/passwd"}) == \
        ("c", "Read", {"path": "/etc/passwd"})
    no, yes = Decision(False, "closed", "r"), Decision(True)
    out, code = answer("cursor", {}, no, enforce=True)
    assert out["permission"] == "deny" and "closed" in out["user_message"] and code == 0
    assert answer("cursor", {}, no, enforce=False)[0]["permission"] == "allow"            # shadow: it runs
    out, _ = answer("claude-code", {}, no, enforce=True)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny" and "closed" in out["systemMessage"]
    assert answer("codex", {}, yes, enforce=True) == (None, 0)


def test_http_proxy_decides_tool_calls_and_forwards_the_rest():
    import threading
    import urllib.request
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from splabs_gate.mcp_http_proxy import make_handler
    seen = []

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            m = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(m.get("params", {}).get("name") or m["method"])
            data = json.dumps({"jsonrpc": "2.0", "id": m.get("id"), "result": {"ok": True}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Mcp-Session-Id", "sess-1")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()

    settled = []

    def transport(path, body):
        if not path.endswith("/decide"):
            settled.append(path.rsplit("/", 1)[1])
            return 200, {"ok": True}
        ok = body["tool"] != "get-env"
        return 200, {"passes": ok, "reason": "" if ok else "closed", "rule": "get-env:closed" * (not ok), "ref": "r"}
    factory = lambda s: Gate(table="t", session=s, transport=transport)          # noqa: E731
    px = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(f"http://127.0.0.1:{up.server_port}/mcp", "t", "a", factory))
    threading.Thread(target=px.serve_forever, daemon=True).start()
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def post(m):
        r = op.open(urllib.request.Request(f"http://127.0.0.1:{px.server_port}/mcp", json.dumps(m).encode(),
                                           headers={"Content-Type": "application/json", "Mcp-Session-Id": "sess-1"}), timeout=10)
        return json.loads(r.read())
    assert post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})["result"] == {"ok": True}
    assert post({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {}}})["result"] == {"ok": True}
    r = post({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get-env", "arguments": {}}})
    assert r["result"]["isError"] and "closed" in r["result"]["content"][0]["text"]
    assert seen == ["initialize", "echo"]                       # the refused call never reached the server
    assert settled == ["ran"]                                   # the passed call was confirmed by its answer
    up.shutdown(); px.shutdown()
