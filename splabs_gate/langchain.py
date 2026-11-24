"""LangChain and LangGraph: each tool an agent may call is decided by the gate before it runs.

    from splabs_gate import Gate
    from splabs_gate.langchain import gate_tools

    tools = gate_tools([search_orders, refund_order], Gate(table="shop_agent", agent="support-bot"))
    agent = create_react_agent(llm, tools)          # or AgentExecutor, ToolNode, bind_tools ...

The wrapped tool keeps the name, description and argument schema the model sees; the gate is asked with the tool's
name and the arguments the model gave. A call that does not pass does not run, and the model reads the gate's
reason as the tool's output. Needs `langchain-core` (imported only here).
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from .client import Gate
from .guard import acall_guarded, call_guarded


def gate_tool(tool, gate: Gate, on_deny: str = "message"):
    """One LangChain tool behind the gate."""
    from langchain_core.tools import BaseTool, StructuredTool, Tool

    if not isinstance(tool, BaseTool):
        raise TypeError("gate_tool takes a LangChain tool (BaseTool); decorate a plain function with @tool first")
    name = tool.name

    if tool.args_schema is None:                          # a tool of one text input
        def run_text(tool_input: str) -> Any:
            return call_guarded(gate, name, {"tool_input": tool_input}, lambda: tool.invoke(tool_input), on_deny)

        async def arun_text(tool_input: str) -> Any:
            return await acall_guarded(gate, name, {"tool_input": tool_input}, lambda: tool.ainvoke(tool_input), on_deny)
        return Tool(name=name, description=tool.description, func=run_text, coroutine=arun_text,
                    return_direct=tool.return_direct)

    def run(**kwargs: Any) -> Any:
        return call_guarded(gate, name, kwargs, lambda: tool.invoke(kwargs), on_deny)

    async def arun(**kwargs: Any) -> Any:
        return await acall_guarded(gate, name, kwargs, lambda: tool.ainvoke(kwargs), on_deny)
    return StructuredTool.from_function(func=run, coroutine=arun, name=name, description=tool.description,
                                        args_schema=tool.args_schema, infer_schema=False,
                                        return_direct=tool.return_direct)


def gate_tools(tools: Iterable, gate: Gate, on_deny: str = "message", skip: Optional[Iterable[str]] = None) -> list:
    """Every tool of the list behind the gate, except those named in `skip`."""
    skip = set(skip or ())
    return [t if t.name in skip else gate_tool(t, gate, on_deny) for t in tools]
