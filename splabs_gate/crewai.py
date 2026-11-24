"""CrewAI: each tool a crew's agent may call is decided by the gate before it runs.

    from crewai import Agent
    from splabs_gate import Gate
    from splabs_gate.crewai import gate_tools

    analyst = Agent(role="...", goal="...", backstory="...",
                    tools=gate_tools([search_orders, refund_order], Gate(table="shop_agent", agent="analyst")))

The wrapped tool keeps the name, description and argument schema the model sees; the gate is asked with the tool's
name and the arguments the model gave. A call that does not pass does not run, and the agent reads the gate's
reason as the tool's output. Needs `crewai` (imported only here).
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from .client import Gate
from .guard import acall_guarded, call_guarded


def gate_tool(tool, gate: Gate, on_deny: str = "message"):
    """One CrewAI tool behind the gate."""
    from crewai.tools import BaseTool
    from pydantic import PrivateAttr

    if not isinstance(tool, BaseTool):
        raise TypeError("gate_tool takes a CrewAI tool (crewai.tools.BaseTool or one made with @tool)")
    name = tool.name

    class GatedTool(BaseTool):
        _inner: Any = PrivateAttr()

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            asked = kwargs if not args else {"input": args[0] if len(args) == 1 else list(args), **kwargs}
            return call_guarded(gate, name, asked, lambda: self._inner.run(*args, **kwargs), on_deny)

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            asked = kwargs if not args else {"input": args[0] if len(args) == 1 else list(args), **kwargs}
            return await acall_guarded(gate, name, asked, lambda: self._inner.arun(*args, **kwargs), on_deny)

    gated = GatedTool(name=name, description=tool.description, args_schema=tool.args_schema,
                      result_as_answer=tool.result_as_answer)
    gated._inner = tool
    return gated


def gate_tools(tools: Iterable, gate: Gate, on_deny: str = "message", skip: Optional[Iterable[str]] = None) -> list:
    """Every tool of the list behind the gate, except those named in `skip`."""
    skip = set(skip or ())
    return [t if t.name in skip else gate_tool(t, gate, on_deny) for t in tools]
