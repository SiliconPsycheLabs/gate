"""The OpenAI Agents SDK (`openai-agents`): each function tool is decided by the gate before it runs.

    from agents import Agent, Runner
    from splabs_gate import Gate
    from splabs_gate.openai_agents import gate_agent

    agent = gate_agent(Agent(name="support", tools=[refund_order, send_mail]), Gate(table="shop_agent"))
    Runner.run_sync(agent, "...")

`gate_agent` returns a copy of the agent whose function tools ask the gate first; `gate_function_tool` does it for
one tool. The model sees the same tool; a call that does not pass does not run, and the model reads the gate's
reason as the tool's output. Hosted tools (web search, file search, computer use) run on OpenAI's side and are not
function calls: put them behind the gate by leaving them out of the agent. Works with any model the SDK drives
(OpenAI, or a vLLM / Ollama server through its OpenAI-compatible API). Imports nothing from `agents` itself.
"""
from __future__ import annotations

import dataclasses
import json
from typing import Iterable, Optional

from .client import Gate
from .guard import acall_guarded


def gate_function_tool(tool, gate: Gate, on_deny: str = "message"):
    """One `FunctionTool` behind the gate (other tools are returned as they are)."""
    if not (dataclasses.is_dataclass(tool) and hasattr(tool, "on_invoke_tool")):
        return tool
    inner, name = tool.on_invoke_tool, tool.name

    async def on_invoke_tool(ctx, raw: str):
        try:
            args = json.loads(raw) if raw else {}
        except ValueError:
            args = {"input": raw}
        return await acall_guarded(gate, name, args, lambda: inner(ctx, raw), on_deny)
    return dataclasses.replace(tool, on_invoke_tool=on_invoke_tool)


def gate_agent(agent, gate: Gate, on_deny: str = "message", skip: Optional[Iterable[str]] = None):
    """A copy of the agent with its function tools behind the gate, except those named in `skip`."""
    skip = set(skip or ())
    tools = [t if getattr(t, "name", None) in skip else gate_function_tool(t, gate, on_deny) for t in agent.tools]
    return agent.clone(tools=tools)
