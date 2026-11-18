"""Turn a framework's tool call into a gate action, and run the tool only when the gate allows it.

Adapters stay outside the checker: they translate, they never decide.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from . import Gate
from .checker import Decision
from .session import Session

# How common tool names map to gate action types and which argument holds what.
DEFAULT_TOOL_MAP: dict[str, dict[str, str]] = {
    "bash": {"type": "shell", "command": "command"},
    "shell": {"type": "shell", "command": "command"},
    "run_command": {"type": "shell", "command": "command"},
    "execute_command": {"type": "shell", "command": "command"},
    "terminal": {"type": "shell", "command": "command"},
    "read_file": {"type": "file.read", "path": "path"},
    "write_file": {"type": "file.write", "path": "path", "content": "content"},
    "edit_file": {"type": "file.write", "path": "path"},
    "str_replace_editor": {"type": "file.write", "path": "path"},
    "delete_file": {"type": "file.delete", "path": "path"},
    "fetch": {"type": "http", "url": "url", "method": "method"},
    "http_request": {"type": "http", "url": "url", "method": "method", "body": "body"},
    "web_fetch": {"type": "http", "url": "url"},
}


def action_from_tool_call(name: str, arguments: dict | str, tool_map: dict | None = None) -> dict:
    tool_map = tool_map or DEFAULT_TOOL_MAP
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments or "{}")
        except json.JSONDecodeError:
            return {"type": "unknown", "tool": name, "raw_arguments": arguments}
    spec = tool_map.get(name)
    if not spec:
        return {"type": "unknown", "tool": name, "arguments": arguments}
    action: dict[str, Any] = {"type": spec["type"], "tool": name}
    for field, arg_name in spec.items():
        if field == "type":
            continue
        if arg_name in arguments:
            action[field] = arguments[arg_name]
    return action


def action_from_openai_tool_call(call: Any, tool_map: dict | None = None) -> dict:
    """Accepts an OpenAI-style tool call (object or dict): {"function": {"name": ..., "arguments": "..."}}."""
    fn = call["function"] if isinstance(call, dict) else call.function
    name = fn["name"] if isinstance(fn, dict) else fn.name
    args = fn["arguments"] if isinstance(fn, dict) else fn.arguments
    return action_from_tool_call(name, args, tool_map)


def guarded(gate: Gate, session: Session, execute: Callable[[dict], str], agent: str = "agent",
            on_confirm: Callable[[Decision], bool] | None = None) -> Callable[[dict], str]:
    """Wrap a tool executor. The returned function runs `execute(action)` only on allow, or on confirm when
    `on_confirm` returns True; otherwise it returns the gate's fixed reply as the tool result."""

    def run(action: dict) -> str:
        d = gate.check(action, session=session, agent=agent)
        if d.allowed:
            return execute(action)
        if d.outcome == "confirm" and on_confirm is not None and on_confirm(d):
            gate.approve(d, session)
            return execute(action)
        return d.reply

    return run
