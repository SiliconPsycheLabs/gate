"""Put the gate in front of any Python function an agent calls: the call is decided before it runs.

    from splabs_gate import Gate
    from splabs_gate.guard import guard

    gate = Gate(table="crm_agent", agent="support-bot")

    @guard(gate)
    def send_mail(to: str, subject: str, body: str = "") -> str:
        ...

`send_mail(...)` asks the gate with the function's name and its arguments (defaults included, by name). When the
call passes it runs and the gate is told it ran (`ran`, with the result when it is text or JSON); when it raises,
the gate is told it did not run (`release`) and the error goes on. When the call does not pass the function does
not run: the agent gets the gate's reason as the function's return value (`on_deny="message"`, the default, since
an agent reads a tool's output), or `GateDenied` is raised (`on_deny="raise"`).

The framework adapters (`splabs_gate.langchain`, `splabs_gate.openai_agents`, `splabs_gate.crewai`) all go through
`call_guarded` / `acall_guarded` here. Nothing in this module holds a rule.
"""
from __future__ import annotations

import asyncio
import functools
import inspect
import json
from typing import Any, Awaitable, Callable, Optional

from .client import Decision, Gate


class GateDenied(PermissionError):
    """Raised by a guarded call that did not pass, when `on_deny="raise"`."""

    def __init__(self, decision: Decision):
        super().__init__(decision.message())
        self.decision = decision


def plain(args: Any) -> dict:
    """The arguments as JSON can carry them: what is not JSON is sent as its text."""
    if not isinstance(args, dict):
        args = {"input": args}
    return json.loads(json.dumps(args, default=str))


def result_text(out: Any) -> Optional[str]:
    """What the gate is told the call returned: text as it is, JSON as JSON, anything else nothing."""
    if isinstance(out, str):
        return out
    try:
        return json.dumps(out)
    except (TypeError, ValueError):
        return None


def _denied(d: Decision, on_deny: str):
    if on_deny == "raise":
        raise GateDenied(d)
    return d.message()


def call_guarded(gate: Gate, tool: str, args: Any, run: Callable[[], Any], on_deny: str = "message") -> Any:
    """Ask the gate, then run the call only when it passes."""
    d = gate.decide(tool, plain(args))
    if not d.passes:
        return _denied(d, on_deny)
    try:
        out = run()
    except BaseException:
        gate.release(d)
        raise
    gate.ran(d, result_text(out))
    return out


async def acall_guarded(gate: Gate, tool: str, args: Any, run: Callable[[], Awaitable[Any]],
                        on_deny: str = "message") -> Any:
    """The same for a coroutine. The client is blocking, so it is asked off the event loop."""
    d = await asyncio.to_thread(gate.decide, tool, plain(args))
    if not d.passes:
        return _denied(d, on_deny)
    try:
        out = await run()
    except BaseException:
        await asyncio.to_thread(gate.release, d)
        raise
    await asyncio.to_thread(gate.ran, d, result_text(out))
    return out


def guard(gate: Gate, name: Optional[str] = None, on_deny: str = "message"):
    """Decorator: the function (plain or `async`) is decided by the gate under `name` (default: its own name)."""
    if on_deny not in ("message", "raise"):
        raise ValueError("on_deny is 'message' or 'raise'")

    def wrap(fn):
        sig, tool = inspect.signature(fn), name or fn.__name__

        def args_of(a, k):
            bound = sig.bind(*a, **k)
            bound.apply_defaults()
            return dict(bound.arguments)

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def ainner(*a, **k):
                return await acall_guarded(gate, tool, args_of(a, k), lambda: fn(*a, **k), on_deny)
            return ainner

        @functools.wraps(fn)
        def inner(*a, **k):
            return call_guarded(gate, tool, args_of(a, k), lambda: fn(*a, **k), on_deny)
        return inner
    return wrap
