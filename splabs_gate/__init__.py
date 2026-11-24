"""splabs_gate: connect an agent to the gate (the table engine at /api/gate/table/v1).

Every action an agent is about to take is sent to the gate before it runs; the answer is passes, or does not pass
with a fixed reason the agent reads. The adapters here only carry actions to the gate and answers back: they hold no
rule (the rules are the account's tables, kept and published in the console at /gate/console).

    from splabs_gate import Gate
    gate = Gate(table="crm_agent", session="ticket-4711", agent="support-bot")
    d = gate.decide("send_mail", {"to": "x@acme.example", "subject": "..."})
    if d.passes: ...run it...; gate.ran(d)
    else: tell the agent d.reason

Adapters: `splabs_gate.mcp_proxy` (any MCP client: Claude Desktop, Cursor, Windsurf, ...), `splabs_gate.openai`
(function calling of OpenAI and of every server that speaks its API: vLLM, Ollama, ...), `splabs_gate.guard` (a
decorator for any Python function an agent calls), `splabs_gate.langchain` (LangChain and LangGraph tools),
`splabs_gate.openai_agents` (the OpenAI Agents SDK), `splabs_gate.crewai` (CrewAI). Each framework is imported only
by its own adapter.
"""
from .client import Decision, Gate, GateUnreachable  # noqa: F401
from . import openai as openai_tools  # noqa: E402,F401  function calling (OpenAI, vLLM, Ollama ...)

__all__ = ["Gate", "Decision", "GateUnreachable"]
__version__ = "0.1.0"
