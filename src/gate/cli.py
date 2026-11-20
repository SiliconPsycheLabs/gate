"""Command line: gate check | validate | replay | packs."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

import cedarpy

from . import PACKS, Gate, pack_paths, packs_dir
from .checker import PolicySet
from .config import Config
from .schema import schema_json

EXIT = {"allow": 0, "deny": 1, "confirm": 2}


def _gate(args) -> Gate:
    config = Config.load(args.config) if args.config else Config()
    paths = pack_paths(args.pack) if args.pack else []
    paths += [Path(p) for p in (args.policies or [])]
    if not paths:
        sys.exit("no rules: pass --pack and/or --policies")
    return Gate(PolicySet.from_paths(paths), config)


def cmd_check(args) -> int:
    g = _gate(args)
    action = json.loads(Path(args.action).read_text()) if args.action != "-" else json.load(sys.stdin)
    session = g.new_session()
    if args.transcript:
        t = json.loads(Path(args.transcript).read_text())
        for m in t.get("user", []):
            session.observe_user(m)
        for k, v in (t.get("tool_outputs") or {}).items():
            session.observe_tool_output(k, v)
        session.secret_read = bool(t.get("secret_read", False))
        session.internal_read = bool(t.get("internal_read", False))
    d = g.check(action, session=session, agent=args.agent)
    out = {"outcome": d.outcome, "rules": d.rules, "reply": d.reply}
    if args.verbose:
        out["record"] = d.record
        out["errors"] = d.errors
    print(json.dumps(out, indent=2))
    return EXIT[d.outcome]


def cmd_validate(args) -> int:
    paths = pack_paths(args.pack) if args.pack else []
    paths += [Path(p) for p in args.paths]
    try:
        ps = PolicySet.from_paths(paths)
    except Exception as e:  # parse errors, duplicate ids, unknown outcomes
        print(f"invalid: {e}")
        return 1
    res = cedarpy.validate_policies(ps.text, schema_json())
    missing_ids = [r.policy_id for r in ps.rules.values() if r.effect == "forbid" and r.rule_id == r.policy_id]
    for e in getattr(res, "errors", []) or []:
        print(f"schema error: {e}")
    for pid in missing_ids:
        print(f"forbid policy {pid} has no @id annotation")
    ok = res.validation_passed and not missing_ids
    print(f"{'valid' if ok else 'invalid'}: {len(ps.rules)} rules")
    return 0 if ok else 1


def cmd_replay(args) -> int:
    """Re-run a decision log against the current rules, in order, one fresh session per logged session."""
    g = _gate(args)
    sessions: dict[str, object] = {}
    changed: Counter = Counter()
    totals: Counter = Counter()
    for line in Path(args.log).read_text().splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        sid = e.get("session", "")
        s = sessions.setdefault(sid, g.new_session())
        d = g.check(e["action"], session=s, agent=e.get("agent", "agent"))
        totals[d.outcome] += 1
        if d.outcome != e.get("outcome"):
            changed[(e.get("outcome"), d.outcome)] += 1
            if args.verbose:
                print(json.dumps({"was": e.get("outcome"), "now": d.outcome, "rules": d.rules, "action": e["action"]}))
    print(json.dumps({"outcomes": dict(totals), "changed": {f"{a}->{b}": n for (a, b), n in changed.items()}}, indent=2))
    return 0


def cmd_packs(args) -> int:
    d = packs_dir()
    for p in ("common",) + PACKS:
        print(p if (d / f"{p}.cedar").is_file() else f"{p} (not installed in {d})")
    return 0


def cmd_mcp_proxy(args) -> int:
    from .integrations import mcp_proxy
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        print("gate mcp-proxy: give the server command after --", file=sys.stderr)
        return 2
    return mcp_proxy.main(args)


def cmd_log_verify(args) -> int:
    from .ledger import verify
    key = os.environ.get("GATE_LOG_HMAC_KEY", "")
    res = verify(args.log, key.encode() if key else None)
    print(json.dumps(res, indent=2))
    return 0 if res["ok"] else 1


def cmd_bundle_keygen(args) -> int:
    from .bundle import keypair
    priv, pub = keypair()
    print(json.dumps({"private": priv, "public": pub}, indent=2))
    return 0


def cmd_bundle_make(args) -> int:
    from . import __version__
    from .bundle import make
    m = make(args.directory, args.packs_version, args.engine_min or __version__,
             os.environ.get("GATE_PACKS_PRIVKEY", "").strip() or None)
    print(json.dumps(m, indent=2))
    return 0


def cmd_bundle_verify(args) -> int:
    from . import __version__
    from .bundle import BundleError, check, configured_pubkey
    try:
        m = check(args.directory, configured_pubkey(), __version__)
    except BundleError as e:
        print(f"refused: {e}")
        return 1
    print("no manifest (unsigned directory)" if m is None else
          f"ok: packs {m.get('packs_version')}, {len(m.get('files', {}))} files"
          + (", signature checked" if configured_pubkey() else ", signature not checked (no GATE_PACKS_PUBKEY)"))
    return 0


def _cc():
    from .integrations import claude_code
    return claude_code


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gate", description="Deterministic gate for AI agent actions.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def rules_opts(p):
        p.add_argument("--pack", help="comma-separated packs: " + ", ".join(PACKS))
        p.add_argument("--policies", nargs="*", help="extra .cedar files or directories")
        p.add_argument("--config", help="operator configuration JSON")
        p.add_argument("--agent", default="agent")
        p.add_argument("-v", "--verbose", action="store_true")

    p = sub.add_parser("check", help="check one action (JSON file or - for stdin); exit 0 allow, 1 deny, 2 confirm")
    p.add_argument("action")
    p.add_argument("--transcript", help="JSON with user messages and tool outputs, for provenance")
    rules_opts(p)
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("validate", help="parse rules and check them against the context schema")
    p.add_argument("paths", nargs="*")
    p.add_argument("--pack")
    p.set_defaults(fn=cmd_validate)

    p = sub.add_parser("replay", help="re-run a decision log against the current rules")
    p.add_argument("log")
    rules_opts(p)
    p.set_defaults(fn=cmd_replay)

    p = sub.add_parser("claude-code", help="put the gate in front of Claude Code (install, status, uninstall)")
    cc = p.add_subparsers(dest="cc_cmd", required=True)
    q = cc.add_parser("install", help="write the hook into Claude Code's settings and the key into ~/.splabs-gate")
    q.add_argument("--key", default=os.environ.get("GATE_TOKEN", ""), help="account key psa_... (or GATE_TOKEN)")
    q.add_argument("--url", default="https://splabs.io")
    q.add_argument("--mode", default="shadow", choices=["shadow", "enforce"])
    q.add_argument("--scope", default="user", choices=["user", "project"],
                   help="user: ~/.claude/settings.json; project: ./.claude/settings.json")
    q.add_argument("--packs", default="coding,harness")
    q.add_argument("--egress", default="", help="hosts allowed without a person, comma separated")
    q.add_argument("--run", default="", help="run label in the gate log (default cc-shadow / cc-enforce)")
    q.add_argument("--redact-file", default="", help="KEY: value file whose values are never sent")
    q.add_argument("--no-check", action="store_true", help="do not test the key against the service")
    q.set_defaults(fn=lambda a: _cc().install(a.key, a.url, a.mode, a.scope, None, a.packs, a.egress, a.run,
                                                a.redact_file, not a.no_check))
    q = cc.add_parser("uninstall", help="remove the hook from Claude Code's settings")
    q.add_argument("--scope", default="user", choices=["user", "project"])
    q.set_defaults(fn=lambda a: _cc().uninstall(a.scope))
    q = cc.add_parser("status", help="config, where the hook is installed, undelivered events, service")
    q.set_defaults(fn=lambda a: _cc().status())
    q = cc.add_parser("hook", help="the hook itself (Claude Code runs it; reads one event on stdin)")
    q.set_defaults(fn=lambda a: _cc().main(["gate"]))

    p = sub.add_parser("packs", help="list the packs and whether they are installed")
    p.set_defaults(fn=cmd_packs)

    p = sub.add_parser("mcp-proxy", help="stdio MCP proxy: forward tools/call to the server only after the gate allows it")
    p.add_argument("--server-name", required=True, help="the server's name in tool names (mcp__<name>__<tool>)")
    p.add_argument("--pack", help="comma-separated packs: " + ", ".join(PACKS))
    p.add_argument("--policies", nargs="*", help="extra .cedar files or directories")
    p.add_argument("--config", help="owner configuration JSON (a task contract goes in its 'contract' field)")
    p.add_argument("--task", default="", help="the task the agent was given: the session's user message")
    p.add_argument("--task-file", default="", help="read the task from a file")
    p.add_argument("--log", default="", help="hash-chained decision log (JSON lines)")
    p.add_argument("--agent", default="agent")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- then the MCP server command")
    p.set_defaults(fn=cmd_mcp_proxy)

    p = sub.add_parser("log", help="the hash-chained decision log")
    lg = p.add_subparsers(dest="log_cmd", required=True)
    q = lg.add_parser("verify", help="check that no line was changed, removed or moved; exit 0 if intact, 1 if not")
    q.add_argument("log")
    q.set_defaults(fn=cmd_log_verify)

    p = sub.add_parser("bundle", help="signed rule-pack bundles")
    bd = p.add_subparsers(dest="bundle_cmd", required=True)
    q = bd.add_parser("keygen", help="print a new Ed25519 key pair (base64): keep the private one secret")
    q.set_defaults(fn=cmd_bundle_keygen)
    q = bd.add_parser("make", help="write manifest.json (and manifest.sig with GATE_PACKS_PRIVKEY) for a packs directory")
    q.add_argument("directory")
    q.add_argument("--packs-version", required=True)
    q.add_argument("--engine-min", default=None, help="default: this engine's version")
    q.set_defaults(fn=cmd_bundle_make)
    q = bd.add_parser("verify", help="check a packs directory against its manifest and, with GATE_PACKS_PUBKEY, its signature")
    q.add_argument("directory")
    q.set_defaults(fn=cmd_bundle_verify)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
