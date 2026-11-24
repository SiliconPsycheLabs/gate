"""The gate in front of coding agents that run hooks before a tool call: Claude Code, OpenAI Codex CLI, Cursor.

The agent runs this command before each tool call and passes the call as JSON on stdin; the command asks the gate
(`/api/gate/table/v1/manager/decide`) and prints the agent's own answer format. Nothing here holds a rule.

    python -m splabs_gate.hooks --agent claude-code --table coding_agent      (or: codex, cursor)

Pass the event on stdin untouched: a wrapper script that does `echo "$IN"` in `sh` turns every `\n` inside the JSON
into a line break, the event no longer reads, and the call is refused.

Settings: GATE_URL, GATE_TOKEN (a gate key from the console), GATE_HOOK_MODE = shadow (default: the decision is
recorded on the tape and the call always runs) or enforce (a call that does not pass is refused, and so is any call
the gate could not decide).

Wiring:
- Claude Code, `.claude/settings.json`:
    {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command",
      "command": "python -m splabs_gate.hooks --agent claude-code --table coding_agent"}]}]}}
- Codex CLI, `~/.codex/hooks.json` or `.codex/hooks.json` (the same shape, event `PreToolUse`), then trust it in `/hooks`.
- Cursor, `.cursor/hooks.json`:
    {"version": 1, "hooks": {"preToolUse": [{"command": "python -m splabs_gate.hooks --agent cursor --table coding_agent",
      "failClosed": true}], "beforeShellExecution": [...same...], "beforeMCPExecution": [...same...],
      "beforeReadFile": [...same...]}}

The doors of the table, whichever agent asks: `Bash` / `Shell` `{"command"}`; file tools (`Read`, `Write`, `Edit`,
`Grep`, `Glob`, `Delete`, `apply_patch` with its patch as `command`) `{"path"}` or `{"command"}`; every other tool
(MCP tools included) `{"arguments": <its input>}`.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

from .client import Decision, Gate

PATH_OF = {"Read": "file_path", "Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "Delete": "file_path",
           "NotebookEdit": "notebook_path", "Glob": "path", "Grep": "path", "LS": "path"}


def door_args(tool: str, ti: dict, cwd: str = "") -> tuple[str, dict]:
    ti = ti if isinstance(ti, dict) else {}
    if tool in ("Bash", "Shell"):
        return tool, {"command": str(ti.get("command", ""))}
    if tool == "apply_patch":
        return tool, {"command": str(ti.get("command", ti.get("patch", "")))}
    if tool in PATH_OF:
        return tool, {"path": str(ti.get(PATH_OF[tool]) or ti.get("path") or cwd)}
    return tool, {"arguments": ti}


_PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$", re.MULTILINE)


def patch_paths(patch: str, cwd: str = "") -> list[str]:
    """The files a patch in Codex's `apply_patch` format touches (added, changed, deleted, moved to)."""
    out = []
    for a, b in _PATCH_FILE.findall(patch or ""):
        p = (a or b).strip()
        p = p if os.path.isabs(p) or not cwd else os.path.join(cwd, p)
        if p not in out:
            out.append(p)
    return out


def action(agent: str, ev: dict) -> tuple[str, str, dict]:
    """(session, tool, args) of one hook event."""
    if agent == "cursor":
        session = str(ev.get("conversation_id") or ev.get("generation_id") or "cursor")
        name = ev.get("hook_event_name", "")
        cwd = (ev.get("workspace_roots") or [""])[0]
        if name == "beforeShellExecution":
            return session, "Shell", {"command": str(ev.get("command", ""))}
        if name == "beforeMCPExecution":
            ti = ev.get("tool_input")
            if isinstance(ti, str):
                try:
                    ti = json.loads(ti)
                except ValueError:
                    ti = {"_unparsed": ti}
            return session, str(ev.get("tool_name", "")), {"arguments": ti or {}}
        if name == "beforeReadFile":
            return session, "Read", {"path": str(ev.get("file_path", ""))}
        tool, args = door_args(str(ev.get("tool_name", "")), ev.get("tool_input") or {}, cwd)
        return session, tool, args
    session = str(ev.get("session_id") or agent)
    tool, args = door_args(str(ev.get("tool_name", "")), ev.get("tool_input") or {}, str(ev.get("cwd", "")))
    return session, tool, args


def answer(agent: str, ev: dict, d: Decision, enforce: bool) -> tuple[dict | None, int]:
    """What the agent reads, and the exit code. In shadow mode the call always runs."""
    blocked = enforce and not d.passes
    explain = (f"Gate: does not pass ({d.rule}): {d.reason}" if not d.passes else "")
    if agent == "cursor":
        out = {"continue": True, "permission": "deny" if blocked else "allow"}
        if blocked:
            out.update({"user_message": explain, "agent_message": d.message()})
        return out, 0
    if not blocked:
        return ({"systemMessage": explain + " (shadow: it ran)"} if explain else None), 0
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": d.message()}, "systemMessage": explain}, 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="splabs_gate.hooks")
    ap.add_argument("--agent", choices=["claude-code", "codex", "cursor"], required=True)
    ap.add_argument("--table")
    ap.add_argument("--name", default="", help="the agent's name on the tape (default: the --agent value)")
    a = ap.parse_args(argv)
    enforce = os.environ.get("GATE_HOOK_MODE", "shadow").strip().lower() == "enforce"
    try:
        ev = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        ev = {}
    try:
        session, tool, args = action(a.agent, ev)
        if not tool:                                # the event was not read (pass stdin through as it is: a shell
            raise ValueError("no tool name")        # `echo` turns the \n inside the JSON into line breaks)
        gate = Gate(table=a.table, session=session, agent=a.name or a.agent)
        d = gate.decide(tool, args)
        if tool == "apply_patch" and d.passes:      # each file the patch touches is one more question, by its path
            for p in patch_paths(args.get("command", ""), str(ev.get("cwd", ""))):
                d = gate.decide("apply_patch_file", {"path": p})
                if not d.passes:
                    break
    except Exception as e:  # noqa: BLE001  the hook never breaks the agent in shadow; enforce fails closed
        d = Decision(False, f"the gate hook failed ({type(e).__name__}), so the call was not checked", "hook")
    out, code = answer(a.agent, ev, d, enforce)
    if out:
        print(json.dumps(out))
    return code


if __name__ == "__main__":
    sys.exit(main())
