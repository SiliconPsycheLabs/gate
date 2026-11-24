"""The SDK's framework adapters (splabs_gate: guard, langchain, openai_agents, crewai): a tool call goes to
the gate first; a call that does not pass never runs and the agent reads the gate's reason; a call that passes runs
and is confirmed (`ran`), one that raises is given back (`release`). No network: the gate is a fake transport. The
framework tests run where the framework is installed."""
import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from splabs_gate import Gate  # noqa: E402
from splabs_gate.guard import GateDenied, guard  # noqa: E402


def fake():
    sent = []

    def transport(path, body):
        sent.append((path.rsplit("/", 1)[1], body))
        if path.endswith("/decide"):
            ok = body["tool"] not in ("delete_all", "refund") or body["args"].get("amount", 0) <= 100
            ok = ok and body["tool"] != "delete_all"
            return 200, {"passes": ok, "reason": "" if ok else f"{body['tool']} is closed", "ref": f"r{len(sent)}",
                         "rule": "" if ok else f"{body['tool']}:closed"}
        return 200, {"ok": True}
    return Gate(table="t", session="s", agent="a", transport=transport), sent


def test_a_guarded_function_runs_only_when_it_passes():
    gate, sent = fake()
    done = []

    @guard(gate)
    def refund(order: str, amount: int = 10) -> dict:
        done.append(order)
        return {"refunded": amount}

    assert refund("A1") == {"refunded": 10}
    assert "refund is closed" in refund("A2", amount=500)
    assert done == ["A1"]
    assert sent[0] == ("decide", {"table": "t", "session": "s", "agent": "a", "tool": "refund", "args": {"order": "A1", "amount": 10}})
    assert sent[1] == ("ran", {"session": "s", "ref": "r1", "result": json.dumps({"refunded": 10})})
    assert [p for p, _ in sent] == ["decide", "ran", "decide"]

    @guard(gate, name="delete_all", on_deny="raise")
    def wipe():
        done.append("wiped")
    with pytest.raises(GateDenied, match="delete_all is closed"):
        wipe()
    assert "wiped" not in done


def test_a_call_that_raises_is_given_back_and_async_works():
    gate, sent = fake()

    @guard(gate)
    def boom(x: int):
        raise RuntimeError("down")
    with pytest.raises(RuntimeError):
        boom(1)
    assert [p for p, _ in sent] == ["decide", "release"]

    @guard(gate)
    async def lookup(order: str) -> str:
        return "ok " + order
    sent.clear()
    assert asyncio.run(lookup("B2")) == "ok B2"
    assert [p for p, _ in sent] == ["decide", "ran"] and sent[1][1]["result"] == "ok B2"


def test_langchain_tools_behind_the_gate():
    pytest.importorskip("langchain_core")
    from langchain_core.tools import Tool, tool
    from splabs_gate.langchain import gate_tools
    gate, sent = fake()
    done = []

    @tool
    def refund(order: str, amount: int) -> str:
        """Refund an order."""
        done.append(order)
        return f"refunded {amount}"
    shout = Tool(name="shout", description="say it loud", func=lambda s: s.upper())
    g_refund, g_shout = gate_tools([refund, shout], gate)
    assert g_refund.name == "refund" and g_refund.args == refund.args and g_refund.description == refund.description
    assert g_refund.invoke({"order": "A1", "amount": 50}) == "refunded 50"
    assert "refund is closed" in g_refund.invoke({"order": "A2", "amount": 900})
    assert asyncio.run(g_refund.ainvoke({"order": "A3", "amount": 5})) == "refunded 5"
    assert g_shout.invoke("hi") == "HI"
    assert done == ["A1", "A3"]
    asked = [b for p, b in sent if p == "decide"]
    assert [(b["tool"], b["args"]) for b in asked] == [("refund", {"order": "A1", "amount": 50}), ("refund", {"order": "A2", "amount": 900}),
                                                      ("refund", {"order": "A3", "amount": 5}), ("shout", {"tool_input": "hi"})]
    call = {"name": "refund", "args": {"order": "A4", "amount": 7}, "id": "c1", "type": "tool_call"}
    assert g_refund.invoke(call).content == "refunded 7"      # as a model's tool call reaches it in an agent loop


def test_openai_agents_function_tools_behind_the_gate():
    pytest.importorskip("agents")
    from agents import Agent, function_tool
    from agents.tool_context import ToolContext
    from splabs_gate.openai_agents import gate_agent
    gate, sent = fake()
    done = []

    @function_tool
    def refund(order: str, amount: int) -> str:
        """Refund an order."""
        done.append(order)
        return f"refunded {amount}"
    agent = gate_agent(Agent(name="support", tools=[refund]), gate)
    g = agent.tools[0]
    assert g.name == "refund" and g.params_json_schema == refund.params_json_schema
    def call(args):                                          # the context the SDK's runner gives a tool call
        raw = json.dumps(args)
        return asyncio.run(g.on_invoke_tool(ToolContext(None, tool_name="refund", tool_call_id="c1", tool_arguments=raw), raw))
    assert call({"order": "A1", "amount": 20}) == "refunded 20"
    assert "refund is closed" in call({"order": "A2", "amount": 900})
    assert done == ["A1"] and [p for p, _ in sent] == ["decide", "ran", "decide"]
    assert sent[0][1]["args"] == {"order": "A1", "amount": 20}


def test_crewai_tools_behind_the_gate():
    pytest.importorskip("crewai")
    from crewai.tools import tool
    from splabs_gate.crewai import gate_tools
    gate, sent = fake()
    done = []

    @tool("refund")
    def refund(order: str, amount: int) -> str:
        """Refund an order."""
        done.append(order)
        return f"refunded {amount}"
    (g,) = gate_tools([refund], gate)
    assert g.name == "refund" and g.args_schema.model_json_schema() == refund.args_schema.model_json_schema()
    assert g.run(order="A1", amount=20) == "refunded 20"
    assert "refund is closed" in g.run(order="A2", amount=900)
    assert g.to_structured_tool().invoke({"order": "A3", "amount": 1}) == "refunded 1"   # the way a crew calls it
    assert done == ["A1", "A3"]
    assert [b["args"] for p, b in sent if p == "decide"] == [{"order": "A1", "amount": 20}, {"order": "A2", "amount": 900},
                                                            {"order": "A3", "amount": 1}]
