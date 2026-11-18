"""The gate in front of Claude Code's tool calls: install it, and the hook Claude Code runs.

    gate claude-code install --key psa_gate_...        # once; writes the hook into ~/.claude/settings.json
    gate claude-code status
    gate claude-code uninstall

Claude Code runs `python -m gate.integrations.claude_code` on its hook events and passes each event as JSON on stdin:

    UserPromptSubmit   -> observe user          (what the person asked)
    PreToolUse         -> check                 (the action, BEFORE it runs)
    PostToolUse        -> observe tool_output   (so the gate knows where each value came from)
    PostToolUseFailure -> observe tool_output   (a call that ran and failed)
    Stop               -> closes the person's answers of the turn (enforce mode)

Two modes:

  shadow (default)  Never decides. Every event is appended to a local spool (~/.splabs-gate/spool) and a background
                    process sends it to the gate service in order. A tool call is not delayed and never blocked; the
                    log shows what WOULD have happened.
  enforce           PreToolUse waits for the gate: deny -> Claude Code refuses the call and the model reads the
                    rule's fixed reply; confirm -> Claude Code asks the person; allow -> Claude Code's own
                    permission settings apply. If the service cannot be reached (or the account's decisions are
                    spent), this package decides on the machine with the packs as shipped, from the same spool.

Installed as a Claude Code plugin instead (`/plugin install splabs-gate --marketplace SiliconPsycheLabs/gate`), Claude
Code runs a copy of this file shipped in claude-code-plugin/hooks/gate_hook.py (standard library only), with --plugin and passes the key and the mode it asked for as
CLAUDE_PLUGIN_OPTION_API_KEY / _MODE / _EGRESS_HOSTS / _RUN. If both are installed, the plugin's hook stands down.

Settings live in ~/.splabs-gate/config.json (written by `install`, mode 600); environment variables override them:
GATE_HOOK_MODE, GATE_HOOK_RUN, GATE_HOOK_PACKS, GATE_EGRESS_HOSTS, GATE_URL, GATE_TOKEN, GATE_REDACT_FILE,
GATE_HOOK_DIR. Values of the redact file (KEY: value or KEY=value lines, values of 12+ characters) are replaced by
[REDACTED:KEY] in everything sent. macOS and Linux.

The hook never fails Claude Code: in shadow mode any error is swallowed; in enforce mode a PreToolUse that cannot be
checked is refused.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

BASE = "/api/gate/v1"
MAX_TEXT = 100_000            # characters of one observed text (the service accepts up to 400,000)
MAX_ACTION = 60_000           # bytes of one action (the service accepts up to 64 KB)
MAX_FIELD = 2_000             # a long string value inside an MCP tool's arguments is cut to this
CHECK_TIMEOUT = 8             # seconds, enforce mode
SEND_TIMEOUT = 10

# Claude Code built-ins that are not a shell, a file or an HTTP request go to the gate as `tool` actions.
FILE_READ_TOOLS = {"Read": "file_path", "Glob": "path", "Grep": "path", "LS": "path"}
FILE_WRITE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path",
                    "NotebookEdit": "notebook_path"}


# ---------------------------------------------------------------- settings

def _home() -> Path:
    return Path(os.environ.get("GATE_HOOK_DIR") or Path.home() / ".splabs-gate")


_CONFIG: dict | None = None


def as_plugin() -> bool:
    """Run by the Claude Code plugin (its hook passes --plugin)."""
    return "--plugin" in sys.argv[1:] or os.environ.get("GATE_HOOK_PLUGIN") == "1"


def config() -> dict:
    """~/.splabs-gate/config.json, written by `gate claude-code install`. Empty when absent, and not read when the
    plugin runs the hook: the plugin's settings are the options Claude Code asked for."""
    global _CONFIG
    if _CONFIG is None and as_plugin():
        _CONFIG = {}
    if _CONFIG is None:
        try:
            _CONFIG = json.loads((_home() / "config.json").read_text())
        except (OSError, ValueError):
            _CONFIG = {}
    return _CONFIG


# Installed as a Claude Code plugin, the settings come from the options Claude Code asked for when the plugin was
# enabled; Claude Code passes them to the hook as CLAUDE_PLUGIN_OPTION_<KEY> (the key in its secure store).
PLUGIN_OPTIONS = {"GATE_TOKEN": "API_KEY", "GATE_HOOK_MODE": "MODE", "GATE_EGRESS_HOSTS": "EGRESS_HOSTS",
                  "GATE_HOOK_RUN": "RUN"}


def setting(env: str, key: str, default: str = "") -> str:
    v = os.environ.get(env)
    if v is not None and v != "":
        return v
    opt = PLUGIN_OPTIONS.get(env)
    if opt:
        v = os.environ.get("CLAUDE_PLUGIN_OPTION_" + opt)
        if v is not None and v.strip() != "":
            return v.strip()
    v = config().get(key, default)
    if isinstance(v, list):
        return ",".join(str(x) for x in v)
    return str(v) if v is not None else default


def mode() -> str:
    m = setting("GATE_HOOK_MODE", "mode", "shadow").strip().lower()
    return m if m in ("shadow", "enforce") else "shadow"


def state_dir() -> Path:
    d = _home()
    (d / "spool").mkdir(parents=True, exist_ok=True)
    return d


def project_dir(event: dict) -> str:
    return os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd()


def _sid(event: dict) -> str:
    raw = str(event.get("session_id") or "no-session")
    return re.sub(r"[^A-Za-z0-9_.-]", "_", raw)[:120]


# ---------------------------------------------------------------- redaction

_REDACT_CACHE: list[tuple[str, str]] | None = None


def _redactions() -> list[tuple[str, str]]:
    """(value, replacement) pairs, longest value first, from the redact file."""
    global _REDACT_CACHE
    if _REDACT_CACHE is not None:
        return _REDACT_CACHE
    path = setting("GATE_REDACT_FILE", "redact_file", "")
    pairs: dict[str, str] = {}
    if path and Path(path).exists():
        for line in Path(path).read_text(errors="replace").splitlines():
            m = re.match(r"^\s*[-*]?\s*`?([A-Z][A-Z0-9_]{2,})`?\s*[:=]\s*`?([^`\s]+)`?\s*$", line)
            if m and len(m.group(2)) >= 12:
                pairs[m.group(2)] = f"[REDACTED:{m.group(1)}]"
    _REDACT_CACHE = sorted(pairs.items(), key=lambda kv: -len(kv[0]))
    return _REDACT_CACHE


def redact(text: str) -> str:
    for value, repl in _redactions():
        if value in text:
            text = text.replace(value, repl)
    return text


def redact_obj(obj):
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj


# ---------------------------------------------------------------- Claude Code event -> gate action

def _cut(obj, limit: int = MAX_FIELD):
    if isinstance(obj, str):
        return obj if len(obj) <= limit else obj[:limit]
    if isinstance(obj, list):
        return [_cut(x, limit) for x in obj]
    if isinstance(obj, dict):
        return {k: _cut(v, limit) for k, v in obj.items()}
    return obj


def to_action(tool_name: str, tool_input: dict, cwd: str) -> dict:
    """The gate action for one Claude Code tool call. Deterministic: the same call gives the same action."""
    ti = tool_input if isinstance(tool_input, dict) else {}
    if tool_name == "Bash":
        return {"type": "shell", "command": str(ti.get("command", "")), "cwd": cwd}
    if tool_name in FILE_READ_TOOLS:
        return {"type": "file.read", "path": str(ti.get(FILE_READ_TOOLS[tool_name]) or cwd), "cwd": cwd}
    if tool_name in FILE_WRITE_TOOLS:
        return {"type": "file.write", "path": str(ti.get(FILE_WRITE_TOOLS[tool_name]) or ""), "cwd": cwd}
    if tool_name == "WebFetch":
        return {"type": "http", "url": str(ti.get("url", "")), "method": "GET"}
    action = {"type": "tool", "name": tool_name, "arguments": ti}
    if len(json.dumps(action)) > MAX_ACTION:
        action["arguments"] = _cut(ti)
    if len(json.dumps(action)) > MAX_ACTION:
        action["arguments"] = _cut(ti, 200)
    return action


def response_text(resp) -> str:
    if resp is None:
        return ""
    if isinstance(resp, str):
        return resp
    if isinstance(resp, dict) and ("stdout" in resp or "stderr" in resp):
        return "\n".join(str(resp.get(k) or "") for k in ("stdout", "stderr")).strip()
    try:
        return json.dumps(resp, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(resp)


# ---------------------------------------------------------------- transport

def _token() -> str:
    return setting("GATE_TOKEN", "token", "")


def call(method: str, path: str, payload: dict | None = None, timeout: int = SEND_TIMEOUT) -> tuple[int, object]:
    """One call to the gate service. (status, body); status 0 when the service could not be reached."""
    import http.client
    from urllib.parse import urlsplit
    u = urlsplit(setting("GATE_URL", "url", "https://splabs.io").rstrip("/"))
    conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    try:
        conn = conn_cls(u.hostname, u.port, timeout=timeout)
        headers = {"Authorization": f"Bearer {_token()}", "Content-Type": "application/json",
                   "User-Agent": "splabs-gate-claude-code"}
        conn.request(method, BASE + path, body=json.dumps(payload) if payload is not None else None, headers=headers)
        r = conn.getresponse()
        raw = r.read().decode("utf-8", "replace")
        try:
            return r.status, json.loads(raw)
        except json.JSONDecodeError:
            return r.status, raw
    except OSError:
        return 0, None


# ---------------------------------------------------------------- spool (one per Claude Code session)

class Spool:
    """Append-only, fsync'd, in order. `sent` counts the lines already delivered."""

    def __init__(self, sid: str):
        d = state_dir() / "spool"
        self.path = d / f"{sid}.jsonl"
        self.sent_path = d / f"{sid}.sent"
        self.state_path = d / f"{sid}.state.json"
        self.lock_path = d / f"{sid}.lock"
        self.dirty_path = d / f"{sid}.dirty"

    def append(self, rec: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def lines(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # a line cut by a kill in mid-write
        return out

    def sent(self) -> int:
        try:
            return int(self.sent_path.read_text().strip() or 0)
        except (OSError, ValueError):
            return 0

    def set_sent(self, n: int) -> None:
        tmp = self.sent_path.with_suffix(".tmp")
        tmp.write_text(str(n))
        os.replace(tmp, self.sent_path)

    def state(self) -> dict:
        try:
            return json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            return {}

    def save_state(self, st: dict) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, sort_keys=True))
        os.replace(tmp, self.state_path)


def _open_session(spool: Spool, meta: dict) -> str | None:
    st = spool.state()
    if st.get("gate_session_id"):
        return st["gate_session_id"]
    packs = [p.strip() for p in setting("GATE_HOOK_PACKS", "packs", "coding,harness").split(",") if p.strip()]
    config = {"workspace": meta.get("workspace") or "."}
    egress = [h.strip() for h in setting("GATE_EGRESS_HOSTS", "egress_hosts", "").split(",") if h.strip()]
    if egress:
        config["egress_hosts"] = egress
    body = {"run": meta.get("run"), "role": "worker", "model": meta.get("model") or "claude-code",
            "label": meta.get("label", "")[:200], "packs": packs, "config": config}
    status, r = call("POST", "/sessions", body)
    if status in (400, 422) and "harness" in packs and "unknown pack" in str(r):
        body["packs"] = [p for p in packs if p != "harness"] or ["coding"]   # a service still on gate < 0.1.8
        status, r = call("POST", "/sessions", body)
    if status != 200 or not isinstance(r, dict) or not r.get("session_id"):
        return None
    st.update({"gate_session_id": r["session_id"], "packs": body["packs"]})
    spool.save_state(st)
    return r["session_id"]


def _deliver(spool: Spool, rec: dict) -> tuple[bool, object]:
    """Send one spool record. (delivered, reply). A 4xx other than 409/429 is a record the service will never take:
    it is counted as delivered so it does not block the rest, and kept in the spool file."""
    gid = _open_session(spool, rec["meta"])
    if not gid:
        return False, None
    k = rec["kind"]
    if k == "observe":
        status, r = call("POST", f"/sessions/{gid}/observe", rec["body"])
    elif k == "check":
        status, r = call("POST", f"/sessions/{gid}/check", rec["body"], timeout=rec.get("timeout", SEND_TIMEOUT))
        if status == 200 and isinstance(r, dict) and rec.get("tool_use_id"):
            st = spool.state()
            st.setdefault("seq_by_tool", {})[rec["tool_use_id"]] = {
                "seq": r.get("seq"), "outcome": r.get("outcome"), "rules": r.get("rules") or [],
                "reply": r.get("reply", "")}
            spool.save_state(st)
    elif k == "approve":
        seq = ((spool.state().get("seq_by_tool") or {}).get(rec["tool_use_id"]) or {}).get("seq")
        if seq is None:
            return True, None
        status, r = call("POST", f"/sessions/{gid}/decisions/{int(seq)}/approve",
                         {"approved": bool(rec.get("approved", True))})
    else:
        return True, None
    if status == 200:
        return True, r
    if k == "check" and status == 402 and rec.get("tool_use_id"):
        # the account's gate decision allowance is spent: no decision was taken (#7478 step 4)
        st = spool.state()
        st.setdefault("seq_by_tool", {})[rec["tool_use_id"]] = {"quota": True}
        spool.save_state(st)
    if 400 <= status < 500 and status not in (409, 429):
        return True, r
    return False, r


def drain(spool: Spool, block_seconds: float = 0.0) -> bool:
    """Send every unsent record in order. True when nothing is left. One drainer at a time per session."""
    deadline = time.time() + block_seconds
    with open(spool.lock_path, "w") as lock:
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time() >= deadline:
                    spool.dirty_path.touch()
                    return False
                time.sleep(0.05)
        try:
            while True:
                spool.dirty_path.unlink(missing_ok=True)
                recs, n = spool.lines(), spool.sent()
                while n < len(recs):
                    ok, _ = _deliver(spool, recs[n])
                    if not ok:
                        return False
                    n += 1
                    spool.set_sent(n)
                if not spool.dirty_path.exists():
                    return True
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _spawn_drainer(sid: str) -> None:
    # run this file, not the package: the plugin ships the hook without the engine's dependencies
    argv = [sys.executable, os.path.abspath(__file__), "--drain", sid] + (["--plugin"] if as_plugin() else [])
    subprocess.Popen(argv,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True, env=os.environ.copy())


# ---------------------------------------------------------------- local engine (enforce mode, service unreachable)

def local_decision(spool: Spool, action: dict, workspace: str) -> dict | None:
    """The open-source engine decides here, with the packs installed on this machine (GATE_PACKS_DIR, rule-set
    version 0), from the observations in the spool. None when the engine or the packs are not installed (the plugin
    ships only the hook, the engine ships no rules): the caller refuses."""
    try:
        from gate import Config, Gate
    except ImportError:
        return None
    packs = spool.state().get("packs") or ["coding", "harness"]
    try:
        g = Gate.from_pack(",".join(packs), Config(workspace=workspace))
    except ValueError:
        try:
            g = Gate.from_pack("coding", Config(workspace=workspace))
        except ValueError:
            return None  # no rule packs on this machine (the engine ships none): the caller refuses
    s = g.new_session()
    for rec in spool.lines():
        b = rec.get("body") or {}
        if rec.get("kind") == "observe" and b.get("kind") == "user":
            s.observe_user(b.get("text", ""))
        elif rec.get("kind") == "observe" and b.get("kind") == "tool_output":
            s.observe_tool_output(b.get("tool_id", ""), b.get("text", ""))
    d = g.check(action, session=s)
    return {"outcome": d.outcome, "rules": d.rules, "reply": d.reply + " (decided on this machine: the gate service "
            "was not reachable; packs installed on this machine)"}


# ---------------------------------------------------------------- the hook

def _meta(event: dict) -> dict:
    run = setting("GATE_HOOK_RUN", "run", "") or ("cc-enforce" if mode() == "enforce" else "cc-shadow")
    branch = ""
    try:
        branch = subprocess.run(["git", "-C", project_dir(event), "rev-parse", "--abbrev-ref", "HEAD"],
                                capture_output=True, text=True, timeout=2).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return {"run": run, "workspace": project_dir(event), "model": os.environ.get("GATE_HOOK_MODEL", "claude-code"),
            "label": f"claude-code {event.get('session_id', '')} {branch}".strip()}


def _out(obj: dict | None) -> None:
    if obj:
        sys.stdout.write(json.dumps(obj))


def handle(event: dict) -> dict | None:
    """Process one hook event. Returns the JSON Claude Code reads, or None for no opinion."""
    name = event.get("hook_event_name", "")
    sid = _sid(event)
    spool = Spool(sid)
    st = spool.state()
    if not st.get("meta"):
        st["meta"] = _meta(event)
        spool.save_state(st)
    meta = st["meta"]
    enforce = mode() == "enforce"

    if name in ("UserPromptSubmit", "Stop"):
        # A held call that never produced a PostToolUse by the end of the turn was refused by the person.
        refused = _settle_held(spool, meta)
        if name == "UserPromptSubmit":
            spool.append({"kind": "observe", "meta": meta,
                          "body": {"kind": "user", "text": redact(str(event.get("prompt", "")))[:MAX_TEXT]}})
        if refused or name == "UserPromptSubmit":
            _spawn_drainer(sid)
        return None

    if name in ("PostToolUse", "PostToolUseFailure"):
        tid = str(event.get("tool_use_id") or hashlib.sha1(json.dumps(event.get("tool_input"), sort_keys=True,
                                                                         default=str).encode()).hexdigest()[:16])
        resp = event.get("tool_response") if name == "PostToolUse" else event.get("error")
        text = redact(response_text(resp))[:MAX_TEXT]
        if enforce:
            _settle_held(spool, meta, ran=tid)
        spool.append({"kind": "observe", "meta": meta,
                      "body": {"kind": "tool_output", "tool_id": tid[:200], "text": text}})
        _spawn_drainer(sid)
        return None

    if name != "PreToolUse":
        return None

    action = redact_obj(to_action(str(event.get("tool_name", "")), event.get("tool_input") or {},
                                  str(event.get("cwd") or project_dir(event))))
    tid = str(event.get("tool_use_id") or "")
    rec = {"kind": "check", "meta": meta, "tool_use_id": tid, "body": {"action": action, "agent": "claude-code"}}

    if not enforce:
        spool.append(rec)
        _spawn_drainer(sid)
        return None

    # enforce: everything observed so far must reach the service before this check, then the check itself.
    decision = None
    if drain(spool, block_seconds=CHECK_TIMEOUT):
        rec["timeout"] = CHECK_TIMEOUT
        spool.append(rec)
        if drain(spool, block_seconds=CHECK_TIMEOUT):
            got = (spool.state().get("seq_by_tool") or {}).get(tid)
            if got and got.get("outcome") in ("allow", "deny", "confirm"):
                decision = got
    else:
        rec["body"]["agent"] = "claude-code-offline"
        spool.append(rec)
    quota = bool(((spool.state().get("seq_by_tool") or {}).get(tid) or {}).get("quota"))
    if decision is None:
        decision = local_decision(spool, action, meta["workspace"])
        if decision is not None and quota:
            decision["reply"] = decision["reply"].replace(
                "the gate service was not reachable", "the account's gate decision allowance is spent")
    if decision is None:
        return _pre("deny", "DENIED: the gate could not decide on this action (the gate service was not reachable "
                            "and the local engine is not installed), so it cannot run.")
    if decision["outcome"] == "allow":
        return None
    if decision["outcome"] == "confirm":
        st = spool.state()
        st.setdefault("held_tools", []).append(tid)
        spool.save_state(st)
        return _pre("ask", decision.get("reply") or "HELD by the gate: a person must approve this action.")
    return _pre("deny", decision.get("reply") or "DENIED by the gate.")


def _settle_held(spool: Spool, meta: dict, ran: str | None = None) -> int:
    """Record the person's answer to held calls. With `ran`, that call ran, so the person approved it. Without,
    the turn is over: every held call still open never ran, so the person refused it. Returns answers spooled."""
    st = spool.state()
    held = st.get("held_tools") or []
    answered = [t for t in held if t == ran] if ran is not None else list(held)
    for t in answered:
        spool.append({"kind": "approve", "meta": meta, "tool_use_id": t, "approved": ran is not None})
    if answered:
        st["held_tools"] = [t for t in held if t not in answered]
        spool.save_state(st)
    return len(answered)


def _pre(decision: str, reason: str) -> dict:
    """The hook only ever refuses a call or asks the person: it never approves a call (an allowed action gets no
    answer, so Claude Code's own permission flow applies) and never changes a call's input."""
    if decision == "deny":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": reason}}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                   "permissionDecisionReason": reason}}


# ---------------------------------------------------------------- install / status / uninstall

HOOK_EVENTS = ["UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "Stop"]
_MARK = "gate.integrations.claude_code"


def hook_command() -> str:
    import shlex
    return f"{shlex.quote(sys.executable)} -m {_MARK}"


def settings_path(scope: str, project: str | None = None) -> Path:
    if scope == "project":
        return Path(project or os.getcwd()) / ".claude" / "settings.json"
    return Path.home() / ".claude" / "settings.json"


def _load_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text() or "{}")
    except ValueError:
        raise SystemExit(f"{path} is not valid JSON: fix it first, nothing was changed")


def _strip_ours(hooks: dict) -> dict:
    out = {}
    for ev, groups in (hooks or {}).items():
        kept = []
        for g in groups or []:
            hs = [h for h in (g.get("hooks") or []) if _MARK not in str(h.get("command", ""))]
            if hs:
                kept.append({**g, "hooks": hs})
        if kept:
            out[ev] = kept
    return out


def install(key: str, url: str = "https://splabs.io", mode_: str = "shadow", scope: str = "user",
            project: str | None = None, packs: str = "coding,harness", egress: str = "", run: str = "",
            redact_file: str = "", check: bool = True) -> int:
    if mode_ not in ("shadow", "enforce"):
        raise SystemExit("--mode must be shadow or enforce")
    if not key.startswith("psa_"):
        raise SystemExit("the key starts with psa_ (create one in Settings on splabs.io; a gate-only key is best)")
    cfg = {"url": url.rstrip("/"), "token": key, "mode": mode_, "packs": packs, "egress_hosts": egress,
           "run": run, "redact_file": redact_file}
    global _CONFIG
    _CONFIG = cfg
    if check:
        status, body = call("GET", "/packs", timeout=15)
        if status != 200:
            raise SystemExit(f"the gate service at {cfg['url']} answered {status or 'nothing'} to this key: "
                             f"{str(body)[:200]}")
    home = _home()
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    cpath = home / "config.json"
    cpath.write_text(json.dumps(cfg, indent=2))
    os.chmod(cpath, 0o600)
    spath = settings_path(scope, project)
    settings = _load_settings(spath)
    hooks = _strip_ours(settings.get("hooks") or {})
    cmd = hook_command()
    for ev in HOOK_EVENTS:
        entry = {"hooks": [{"type": "command", "command": cmd, "timeout": 20 if ev == "PreToolUse" else 10}]}
        if ev in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
            entry = {"matcher": "*", **entry}
        hooks.setdefault(ev, []).append(entry)
    settings["hooks"] = hooks
    spath.parent.mkdir(parents=True, exist_ok=True)
    spath.write_text(json.dumps(settings, indent=2) + "\n")
    print(f"Gate hook installed in {spath} ({mode_} mode), config in {cpath}.")
    if plugin_enabled():
        print("The Claude Code plugin splabs-gate@splabs is enabled too: it stands down while this hook is installed.")
    print("Start a new Claude Code session: its actions go to the gate. Decisions: the console at "
          f"{cfg['url']}/gate, run '{run or ('cc-enforce' if mode_ == 'enforce' else 'cc-shadow')}'.")
    if mode_ == "shadow":
        print("Shadow mode records what the gate would do and blocks nothing. When the counter looks right: "
              "gate claude-code install --mode enforce ... (same command, new mode).")
    return 0


def uninstall(scope: str = "user", project: str | None = None) -> int:
    spath = settings_path(scope, project)
    settings = _load_settings(spath)
    before = json.dumps(settings.get("hooks") or {})
    settings["hooks"] = _strip_ours(settings.get("hooks") or {})
    if not settings["hooks"]:
        settings.pop("hooks")
    if json.dumps(settings.get("hooks") or {}) == before:
        print(f"No gate hook in {spath}.")
        return 0
    spath.write_text(json.dumps(settings, indent=2) + "\n")
    print(f"Gate hook removed from {spath}. The config and the spool stay in {_home()}.")
    return 0


def status() -> int:
    cfg = config()
    tok = cfg.get("token", "")
    print(f"config: {_home() / 'config.json'} " + ("(missing: run gate claude-code install)" if not cfg else ""))
    if cfg:
        print(f"  url={cfg.get('url')} mode={mode()} packs={cfg.get('packs')} key={tok[:10]}... "
              f"egress_hosts={cfg.get('egress_hosts') or '-'}")
    for scope in ("user", "project"):
        sp = settings_path(scope)
        on = sp.exists() and _MARK in sp.read_text()
        print(f"hook in {sp}: {'yes' if on else 'no'}")
    print(f"plugin splabs-gate@splabs enabled: {'yes' if plugin_enabled() else 'no'}"
          + (" (stands down: the settings hook decides)" if plugin_enabled() and settings_hook_installed() else ""))
    spool = _home() / "spool"
    sessions = sorted(spool.glob("*.jsonl")) if spool.exists() else []
    pending = 0
    for f in sessions:
        sent = Spool(f.stem).sent()
        pending += max(0, len(Spool(f.stem).lines()) - sent)
    print(f"spool: {len(sessions)} sessions, {pending} events not yet delivered")
    if cfg:
        code, _ = call("GET", "/packs", timeout=10)
        print(f"service: {'reachable' if code == 200 else f'answered {code or 0}'}")
    return 0


PLUGIN_NAMES = ("splabs-gate", "gate")   # "gate" until v0.1.15


def plugin_enabled() -> bool:
    """The plugin splabs-gate@splabs is enabled in the user's Claude Code settings."""
    try:
        s = json.loads(settings_path("user").read_text() or "{}")
    except (OSError, ValueError):
        return False
    return any(k.split("@")[0] in PLUGIN_NAMES and k.endswith("@splabs") and v for k, v in
               (s.get("enabledPlugins") or {}).items())


def settings_hook_installed(project: str | None = None) -> bool:
    """`gate claude-code install` put the hook in the user's or the project's settings."""
    for scope in ("user", "project"):
        try:
            if _MARK in settings_path(scope, project).read_text():
                return True
        except OSError:
            pass
    return False


def main(argv: list[str]) -> int:
    if as_plugin() and settings_hook_installed(os.environ.get("CLAUDE_PROJECT_DIR")):
        return 0  # installed both ways: the settings hook decides, so no action reaches the gate twice
    if len(argv) >= 3 and argv[1] == "--drain":
        try:
            drain(Spool(argv[2]))
        except Exception:
            pass
        return 0
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        return 0
    try:
        _out(handle(event))
    except Exception as exc:  # the hook never breaks Claude Code; enforce mode fails closed on PreToolUse
        if mode() == "enforce" and event.get("hook_event_name") == "PreToolUse":
            _out(_pre("deny", f"DENIED: the gate hook failed ({type(exc).__name__}), so this action cannot be "
                              "checked."))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
