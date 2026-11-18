"""The Claude Code integration: install into settings, the hook end to end against a fake gate service."""
import io
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from gate.integrations import claude_code as cc


class _Svc(BaseHTTPRequestHandler):
    calls = []
    outcome = "allow"

    def log_message(self, *a):
        pass

    def _reply(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        _Svc.calls.append(("GET", self.path, None, self.headers.get("Authorization")))
        self._reply(200, {"packs": []})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        _Svc.calls.append(("POST", self.path, body, self.headers.get("Authorization")))
        if self.path.endswith("/sessions"):
            return self._reply(200, {"session_id": "s-1"})
        if self.path.endswith("/check"):
            return self._reply(200, {"seq": 1, "outcome": _Svc.outcome, "rules": ["r"], "reply": "R"})
        self._reply(200, {"ok": True})


@pytest.fixture
def svc(tmp_path, monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), _Svc)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _Svc.calls, _Svc.outcome = [], "allow"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("GATE_HOOK_DIR", str(tmp_path / ".splabs-gate"))
    for v in ("GATE_HOOK_MODE", "GATE_URL", "GATE_TOKEN", "GATE_HOOK_RUN", "GATE_HOOK_PLUGIN",
              "CLAUDE_PLUGIN_OPTION_API_KEY", "CLAUDE_PLUGIN_OPTION_MODE", "CLAUDE_PLUGIN_OPTION_EGRESS_HOSTS",
              "CLAUDE_PLUGIN_OPTION_RUN"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr(cc, "_CONFIG", None)
    monkeypatch.setattr(cc, "_REDACT_CACHE", None)
    monkeypatch.setattr(cc, "_spawn_drainer", lambda sid: cc.drain(cc.Spool(sid)))
    yield f"http://127.0.0.1:{srv.server_address[1]}", tmp_path
    srv.shutdown()


def _install(url, tmp, **kw):
    secrets = tmp / "secrets.env"
    secrets.write_text("MY_TOKEN=supersecretvalue123\n")
    return cc.install("psa_gate_abc", url=url, redact_file=str(secrets), **kw)


def test_install_writes_config_and_hooks_idempotently(svc):
    url, tmp = svc
    s = tmp / ".claude" / "settings.json"
    s.parent.mkdir()
    s.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command",
                                                                                     "command": "mine.sh"}]}]},
                             "theme": "dark"}))
    assert _install(url, tmp) == 0
    assert _install(url, tmp) == 0
    d = json.loads(s.read_text())
    assert d["theme"] == "dark"
    pre = d["hooks"]["PreToolUse"]
    assert [h["hooks"][0]["command"] for h in pre].count(cc.hook_command()) == 1
    assert any(h["hooks"][0]["command"] == "mine.sh" for h in pre)
    assert set(cc.HOOK_EVENTS) <= set(d["hooks"])
    cfg = tmp / ".splabs-gate" / "config.json"
    assert json.loads(cfg.read_text())["token"] == "psa_gate_abc"
    assert oct(cfg.stat().st_mode & 0o777) == "0o600"
    assert ("GET", "/api/gate/v1/packs", None, "Bearer psa_gate_abc") in _Svc.calls


def test_uninstall_keeps_other_hooks(svc):
    url, tmp = svc
    _install(url, tmp)
    s = tmp / ".claude" / "settings.json"
    d = json.loads(s.read_text())
    d["hooks"]["Stop"].append({"hooks": [{"type": "command", "command": "other.sh"}]})
    s.write_text(json.dumps(d))
    cc.uninstall()
    d = json.loads(s.read_text())
    assert cc._MARK not in json.dumps(d) and d["hooks"]["Stop"][0]["hooks"][0]["command"] == "other.sh"


def test_bad_key_is_refused(svc):
    url, tmp = svc
    with pytest.raises(SystemExit):
        cc.install("sk-wrong", url=url)


def test_shadow_hook_sends_in_order_and_redacts(svc, monkeypatch):
    url, tmp = svc
    _install(url, tmp)
    monkeypatch.setattr(cc, "_CONFIG", None)
    ev = {"session_id": "abc", "cwd": str(tmp)}
    assert cc.handle({**ev, "hook_event_name": "UserPromptSubmit", "prompt": "use supersecretvalue123"}) is None
    assert cc.handle({**ev, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "t1",
                      "tool_input": {"command": "ls"}}) is None
    posts = [(c[1], c[2]) for c in _Svc.calls if c[0] == "POST"]
    assert [p for p, _ in posts] == ["/api/gate/v1/sessions", "/api/gate/v1/sessions/s-1/observe",
                                     "/api/gate/v1/sessions/s-1/check"]
    assert "supersecret" not in json.dumps(posts) and "[REDACTED:MY_TOKEN]" in posts[1][1]["text"]


def test_enforce_deny_reaches_claude_code(svc, monkeypatch):
    url, tmp = svc
    _install(url, tmp, mode_="enforce")
    monkeypatch.setattr(cc, "_CONFIG", None)
    _Svc.outcome = "deny"
    out = cc.handle({"session_id": "e1", "cwd": str(tmp), "hook_event_name": "PreToolUse", "tool_name": "Bash",
                     "tool_use_id": "t1", "tool_input": {"command": "rm -rf /"}})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


TOY_COMMON = """@id("permit-all")
permit (principal, action, resource);

@id("toy-no-eval")
@reason("eval is not allowed here.")
forbid (principal, action, resource)
when { context.n.commands.contains("eval") };
"""


def _toy_packs(d):
    d.mkdir()
    (d / "common.cedar").write_text(TOY_COMMON)
    for p in ("coding", "ops", "strict", "harness"):
        (d / f"{p}.cedar").write_text("")
    return d


def test_enforce_service_down_decides_locally(svc, monkeypatch):
    url, tmp = svc
    monkeypatch.setenv("GATE_PACKS_DIR", str(_toy_packs(tmp / "packs")))
    _install(url, tmp, mode_="enforce")
    cfg = tmp / ".splabs-gate" / "config.json"
    d = json.loads(cfg.read_text())
    d["url"] = "http://127.0.0.1:9"
    cfg.write_text(json.dumps(d))
    monkeypatch.setattr(cc, "_CONFIG", None)
    monkeypatch.setattr(cc, "CHECK_TIMEOUT", 0)
    out = cc.handle({"session_id": "e2", "cwd": str(tmp), "hook_event_name": "PreToolUse", "tool_name": "Bash",
                     "tool_use_id": "t1", "tool_input": {"command": "eval \"$X\""}})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "decided on this machine" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_cli_status_runs(svc, capsys):
    url, tmp = svc
    _install(url, tmp)
    from gate.cli import main
    assert main(["claude-code", "status"]) == 0
    assert "hook in" in capsys.readouterr().out


# ---------------------------------------------------------------- installed as a Claude Code plugin

def _plugin_env(monkeypatch, url, mode="enforce"):
    monkeypatch.setenv("GATE_URL", url)
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_API_KEY", "psa_gate_plugin")
    monkeypatch.setenv("CLAUDE_PLUGIN_OPTION_MODE", mode)
    monkeypatch.setenv("GATE_HOOK_PLUGIN", "1")


def test_plugin_options_drive_the_hook(svc, monkeypatch):
    url, tmp = svc
    _plugin_env(monkeypatch, url)
    _Svc.outcome = "confirm"
    assert cc.mode() == "enforce"
    out = cc.handle({"session_id": "p1", "cwd": str(tmp), "hook_event_name": "PreToolUse", "tool_name": "Bash",
                     "tool_use_id": "t1", "tool_input": {"command": "pip install rich"}})
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert all(c[3] == "Bearer psa_gate_plugin" for c in _Svc.calls)
    assert [c[2]["run"] for c in _Svc.calls if c[1].endswith("/sessions")] == ["cc-enforce"]


def test_environment_overrides_plugin_options(svc, monkeypatch):
    url, _ = svc
    _plugin_env(monkeypatch, url, mode="enforce")
    monkeypatch.setenv("GATE_HOOK_MODE", "shadow")
    assert cc.mode() == "shadow"


def test_plugin_stands_down_when_settings_hook_is_installed(svc, monkeypatch, capsys):
    url, tmp = svc
    _install(url, tmp, mode_="enforce")
    _plugin_env(monkeypatch, url)
    _Svc.calls.clear()
    _Svc.outcome = "deny"
    ev = {"session_id": "p2", "cwd": str(tmp), "hook_event_name": "PreToolUse", "tool_name": "Bash",
          "tool_use_id": "t1", "tool_input": {"command": "sudo true"}}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(ev)))
    capsys.readouterr()
    assert cc.main(["hook"]) == 0
    assert capsys.readouterr().out == "" and _Svc.calls == []


def test_plugin_without_engine_refuses_when_service_is_down(svc, monkeypatch):
    url, tmp = svc
    _plugin_env(monkeypatch, "http://127.0.0.1:9")
    monkeypatch.setattr(cc, "CHECK_TIMEOUT", 0)
    monkeypatch.setattr(cc, "local_decision", lambda *a: None)
    out = cc.handle({"session_id": "p3", "cwd": str(tmp), "hook_event_name": "PreToolUse", "tool_name": "Bash",
                     "tool_use_id": "t1", "tool_input": {"command": "ls"}})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "local engine is not installed" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_plugin_manifest_matches_the_package():
    from pathlib import Path
    import gate
    root = Path(__file__).resolve().parents[1]
    plugin = root / "claude-code-plugin"
    manifest = json.loads((plugin / ".claude-plugin" / "plugin.json").read_text())
    market = json.loads((root / ".claude-plugin" / "marketplace.json").read_text())
    hooks = json.loads((plugin / "hooks" / "hooks.json").read_text())["hooks"]
    assert manifest["version"] == gate.__version__
    entry = market["plugins"][0]
    assert market["name"] == "splabs" and entry["name"] == manifest["name"] == "splabs-gate"
    assert entry["source"] == "./claude-code-plugin" and market["renames"] == {"gate": "splabs-gate"}
    assert sorted(hooks) == sorted(cc.HOOK_EVENTS)
    for groups in hooks.values():
        for g in groups:
            for h in g["hooks"]:
                assert h["command"] == "python3"
                assert h["args"] == ["${CLAUDE_PLUGIN_ROOT}/hooks/gate_hook.py", "--plugin"]


def test_plugin_ships_the_same_hook():
    """claude-code-plugin/hooks/gate_hook.py is a byte copy of the module: copy it when the module changes."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    assert (root / "claude-code-plugin/hooks/gate_hook.py").read_bytes() == \
        (root / "src/gate/integrations/claude_code.py").read_bytes()


def test_hook_never_approves_or_rewrites_a_call():
    for d in ("deny", "ask", "allow", "confirm", ""):
        out = cc._pre(d, "r")["hookSpecificOutput"]
        assert out["permissionDecision"] in ("deny", "ask") and "updatedInput" not in out


def test_plugin_mode_ignores_the_pip_config(svc, monkeypatch):
    url, tmp = svc
    _install(url, tmp, mode_="enforce")
    monkeypatch.setattr(cc, "_CONFIG", None)
    monkeypatch.setenv("GATE_HOOK_PLUGIN", "1")
    assert cc.config() == {} and cc.mode() == "shadow" and cc._token() == ""


def test_enforce_service_down_without_packs_refuses(svc, monkeypatch):
    url, tmp = svc
    monkeypatch.setenv("GATE_PACKS_DIR", str(tmp / "nowhere"))
    _install(url, tmp, mode_="enforce")
    cfg = tmp / ".splabs-gate" / "config.json"
    d = json.loads(cfg.read_text())
    d["url"] = "http://127.0.0.1:9"
    cfg.write_text(json.dumps(d))
    monkeypatch.setattr(cc, "_CONFIG", None)
    monkeypatch.setattr(cc, "CHECK_TIMEOUT", 0)
    out = cc.handle({"session_id": "e3", "cwd": str(tmp), "hook_event_name": "PreToolUse", "tool_name": "Bash",
                     "tool_use_id": "t1", "tool_input": {"command": "ls"}})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
