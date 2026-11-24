"""The gate in front of OpenAI-style function calling: the OpenAI API and every server that speaks it (vLLM, Ollama,
LM Studio, llama.cpp server, Together, Groq ...). Each tool call the model returns is decided before it runs; a call
that does not pass is not run, and the model reads the gate's reason as the tool's answer.

    from splabs_gate import Gate
    from splabs_gate.openai import run_tool_calls
    gate = Gate(table="support_desk", session=ticket_id, agent="support-bot")
    msg = client.chat.completions.create(model=..., messages=messages, tools=tools).choices[0].message
    messages.append(msg)
    messages += run_tool_calls(gate, msg, {"refund": refund, "send_email": send_email})

The table's tools are the function names; their arguments are the function's arguments, as the model wrote them.
Works with the OpenAI SDK's objects and with plain dicts (a raw HTTP answer).
"""
from __future__ import annotations

import json
from typing import Any, Callable, Optional

from .client import Decision, Gate


def _get(o: Any, k: str, default=None):
    return o.get(k, default) if isinstance(o, dict) else getattr(o, k, default)


def tool_calls(message: Any) -> list[tuple[str, str, Any]]:
    """(id, name, arguments) of each tool call of an assistant message. Arguments the model did not write as JSON
    are kept as the raw text: such a call does not fit any tool's form, so it does not pass."""
    out = []
    for c in _get(message, "tool_calls") or []:
        f = _get(c, "function") or {}
        raw = _get(f, "arguments") or "{}"
        try:
            args = json.loads(raw) if isinstance(raw, str) else raw
        except ValueError:
            args = {"_unparsed": raw}
        out.append((_get(c, "id", ""), _get(f, "name", ""), args if isinstance(args, dict) else {"_unparsed": raw}))
    return out


def decide_tool_calls(gate: Gate, message: Any) -> list[tuple[str, str, dict, Decision]]:
    return [(cid, name, args, gate.decide(name, args)) for cid, name, args in tool_calls(message)]


def run_tool_calls(gate: Gate, message: Any, functions: dict[str, Callable[..., Any]],
                   on_decision: Optional[Callable[[str, dict, Decision], None]] = None) -> list[dict]:
    """Decide each tool call, run the ones that pass, and return the `tool` messages to append to the conversation."""
    out = []
    for cid, name, args, d in decide_tool_calls(gate, message):
        if on_decision:
            on_decision(name, args, d)
        if not d.passes:
            content = d.message()
        elif name not in functions:
            gate.release(d)
            content = f"the tool {name} is not available here"
        else:
            try:
                result = functions[name](**args)
            except Exception as e:  # noqa: BLE001  the tool failed: the passed action did not run
                gate.release(d)
                content = f"the tool failed: {type(e).__name__}: {e}"
            else:
                content = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
                gate.ran(d, content)
        out.append({"role": "tool", "tool_call_id": cid, "content": content})
    return out
