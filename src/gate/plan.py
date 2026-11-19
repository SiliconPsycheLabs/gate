"""A plan read as a graph: one decision per step (PSA #7814, GATE-PLAN-01).

A compound shell line (`a && b ; c || d`, several lines), or a list of actions an agent means to take (the tool calls a
model emitted in one turn, the steps of a planned task), is split into steps. Each step is decided by the same rules as
a single action, in order, in a copy of the session, so a step sees what the earlier allowed steps did (a secret read,
a bank-detail change). Edges say which step needs which:

    order   `a && b`, `a || b`: b runs only after a's outcome, so b needs a.
    data    a step that reads, runs or deletes a file an earlier step writes; a step whose arguments name an earlier
            step's output (an explicit edge given by the caller).
    seq     `a ; b`, a new line, `a & b`: b comes after a but does not need it.

A step that needs a held or refused step is blocked: it is never offered on its own. The answer lists the steps that
can run, the ones that wait for a person, the ones refused and the ones blocked. Nothing here is probabilistic: the same
plan in the same session always gets the same graph and the same answer.
"""

from __future__ import annotations

import copy
import re
import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path

import bashlex

from .checker import ALLOW, CONFIRM, DENY

BLOCKED = "blocked"
_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=\S*(?:\s+[A-Za-z_][A-Za-z0-9_]*=\S*)*\s*$")
_CD_RE = re.compile(r"^\s*(?:cd|pushd)(?:\s+(\S+))?\s*$")


@dataclass
class Step:
    index: int
    action: dict
    text: str = ""
    joined_by: str = ""             # the operator before this step in a shell line: "&&", "||", ";", "\n", "&", ""
    needs: list[int] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    outcome: str = ""               # allow | confirm | deny | blocked
    rules: list[str] = field(default_factory=list)
    reply: str = ""
    blocked_by: list[int] = field(default_factory=list)
    normalized: dict = field(default_factory=dict)    # the step's record, as check() saw it


@dataclass
class PlanDecision:
    outcome: str                    # the plan as a whole: allow if every step is allowed, else the strictest step
    steps: list[Step]
    runnable: list[int]
    held: list[int]
    refused: list[int]
    blocked: list[int]
    reply: str
    split: bool                     # False when the plan is a single step (nothing to split)
    whole_outcome: str = ""         # a shell line checked as one action, as check() decides it
    whole_rules: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {**asdict(self), "steps": [asdict(s) for s in self.steps]}


# ------------------------------------------------------------------------------------------------- shell splitting

def split_shell(command: str) -> list[tuple[str, str]]:
    """The steps of a shell line as (text, operator before it). A pipeline, a subshell, a loop, a function, a
    here-document or a line that does not parse stays one step: the single-action rules already read them whole."""
    command = command or ""
    if "<<" in command or not command.strip():
        return [(command, "")]
    try:
        trees = bashlex.parse(command)
    except Exception:  # noqa: BLE001  unparseable: one step, which the single-action rules refuse
        return [(command, "")]
    steps: list[tuple[str, str]] = []
    for ti, tree in enumerate(trees):
        sep = "\n" if ti else ""
        if tree.kind == "list":
            op = sep
            for part in tree.parts:
                if part.kind == "operator":
                    op = part.op
                    continue
                if part.kind == "reservedword":
                    continue
                steps.append((command[part.pos[0]:part.pos[1]], op))
                op = ""
        else:
            steps.append((command[tree.pos[0]:tree.pos[1]], sep))
    # a trailing `&` or `;` is an operator node with nothing after it: nothing to add
    return steps or [(command, "")]


def _shell_steps(action: dict) -> list[Step]:
    parts = split_shell(str(action.get("command", "")))
    out = []
    for i, (text, op) in enumerate(parts):
        out.append(Step(index=i, action={**action, "command": text}, text=text.strip(), joined_by=op))
    return out


# --------------------------------------------------------------------------------------------------------- edges

def _order_edges(steps: list[Step]) -> None:
    for s in steps:
        if s.index and s.joined_by in ("&&", "||"):
            s.needs.append(s.index - 1)
            s.edges.append({"from": s.index - 1, "to": s.index, "kind": "order", "op": s.joined_by})


def _used_paths(step: Step, rec: dict, cwd: str | None) -> set[str]:
    used = set(rec.get("reads") or []) | set(rec.get("deletes") or []) | set(rec.get("paths") or [])
    if step.action.get("type") == "shell":
        w = _words(step.text)
        if w and (w[0].startswith("./") or w[0].startswith("/")):       # a script run by its path
            used.add(str((Path(cwd) / w[0]).resolve()) if cwd and not w[0].startswith("/") else w[0])
    return used


def _words(text: str) -> list[str]:
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


# ---------------------------------------------------------------------------------------------------- the check

def _context_prefix(steps: list[Step], upto: int, cwd: str | None, config=None) -> tuple[str | None, list[str]]:
    """The working directory and the variable assignments the steps before `upto` leave for it."""
    assigns: list[str] = []
    for s in steps[:upto]:
        if s.action.get("type") != "shell" or s.outcome in (DENY, CONFIRM, BLOCKED):
            continue
        m = _CD_RE.match(s.text)
        if m:
            target = m.group(1) or "~"
            if "$" not in target and "`" not in target:
                if target == "~" or target.startswith("~/"):
                    # the agent's home, as the single-action reading resolves `cd ~` (not the gate's own home)
                    target = config.expand_home(target) if config is not None else target
                base = Path(cwd) if cwd else None
                cwd = str((base / target) if base is not None and not target.startswith("/") else Path(target))
        elif _ASSIGN_RE.match(s.text):
            assigns.append(s.text.strip())
    return cwd, assigns


def check_plan(gate, plan: dict, session=None, agent: str = "agent") -> PlanDecision:
    """Decide a plan step by step. `plan` is a shell action (split on its operators and lines) or
    {"type": "plan", "steps": [action, ...], "edges": [[from, to], ...]} for a list of actions; explicit edges are
    data edges given by the caller (step `to` uses the output of step `from`). The session is not changed: each step
    is checked in a copy that carries the effects of the earlier allowed steps."""
    session = session if session is not None else gate.new_session()
    work = copy.deepcopy(session)
    if plan.get("type") == "plan":
        steps = [Step(index=i, action=dict(a), text=_label(a)) for i, a in enumerate(plan.get("steps") or [])]
        for e in plan.get("edges") or []:
            try:
                a, b = int(e[0]), int(e[1])
            except (TypeError, ValueError, IndexError, KeyError):
                continue
            if 0 <= a < b < len(steps) and a not in steps[b].needs:
                steps[b].needs.append(a)
                steps[b].edges.append({"from": a, "to": b, "kind": "data", "given": True})
    elif plan.get("type") == "shell":
        steps = _shell_steps(plan)
    else:
        steps = [Step(index=0, action=dict(plan), text=_label(plan))]
    _order_edges(steps)
    base_cwd = plan.get("cwd") or str(gate.config.workspace_path)
    written: dict[str, int] = {}
    from .normalize import normalize
    for s in steps:
        cwd = base_cwd
        if s.action.get("type") == "shell":
            cwd, assigns = _context_prefix(steps, s.index, base_cwd, gate.config)
            s.action["cwd"] = cwd
            if assigns and not _ASSIGN_RE.match(s.text):
                s.action["command"] = " && ".join(assigns + [s.text])
        rec = normalize(s.action, gate.config)
        for p in sorted(_used_paths(s, rec, cwd)):
            src = written.get(p)
            if src is not None and src != s.index and src not in s.needs:
                s.needs.append(src)
                s.edges.append({"from": src, "to": s.index, "kind": "data", "path": p})
        for p in rec.get("writes") or []:
            written[p] = s.index
        bad = [n for n in s.needs if steps[n].outcome in (DENY, CONFIRM, BLOCKED)]
        if bad:
            s.outcome, s.blocked_by = BLOCKED, sorted(bad)
            s.reply = "BLOCKED: this step needs step(s) " + ", ".join(str(b + 1) for b in s.blocked_by) + \
                      ", which did not pass; it is not run on its own."
            continue
        d = gate.check(s.action, session=work, agent=agent)
        s.outcome, s.rules, s.reply = d.outcome, sorted(d.rules), d.reply
        s.normalized = d.record.get("normalized", {})
    whole = None
    if plan.get("type") == "shell" and len(steps) > 1:
        whole = gate.check(plan, session=copy.deepcopy(session), agent=agent)
        if whole.outcome != ALLOW and all(s.outcome == ALLOW for s in steps):
            # a rule reads the line as a whole (a sequence no single step shows): the plan is never laxer than the
            # line, so no step is offered on its own
            for s in steps:
                s.outcome, s.rules = whole.outcome, sorted(whole.rules)
                s.reply = "TOGETHER: the line as a whole did not pass (" + ", ".join(sorted(whole.rules)) + \
                          "); no single step shows why, so no step is run on its own."
    runnable = [s.index for s in steps if s.outcome == ALLOW]
    held = [s.index for s in steps if s.outcome == CONFIRM]
    refused = [s.index for s in steps if s.outcome == DENY]
    blocked = [s.index for s in steps if s.outcome == BLOCKED]
    outcome = DENY if refused else CONFIRM if (held or blocked) else ALLOW
    return PlanDecision(outcome=outcome, steps=steps, runnable=runnable, held=held, refused=refused, blocked=blocked,
                        reply=_reply(steps), split=len(steps) > 1,
                        whole_outcome=whole.outcome if whole else "", whole_rules=sorted(whole.rules) if whole else [])


def _label(a: dict) -> str:
    t = a.get("type", "")
    if t == "shell":
        return str(a.get("command", ""))
    if t == "tool":
        return str(a.get("name", ""))
    if t == "http":
        return f'{a.get("method", "GET")} {a.get("url", "")}'
    return f'{t} {a.get("path") or " ".join(a.get("argv") or [])}'.strip()


def _reply(steps: list[Step]) -> str:
    if all(s.outcome == ALLOW for s in steps):
        return "ALLOWED: every step of this plan passes."
    lines = []
    for s in steps:
        mark = {ALLOW: "ok", CONFIRM: "held", DENY: "refused", BLOCKED: "blocked"}[s.outcome]
        why = (" (" + ", ".join(s.rules) + ")") if s.rules and s.outcome in (CONFIRM, DENY) else \
              (" (needs step " + ", ".join(str(b + 1) for b in s.blocked_by) + ")") if s.blocked_by else ""
        lines.append(f"step {s.index + 1} {mark}{why}: {s.text[:160]}")
    run = [str(s.index + 1) for s in steps if s.outcome == ALLOW]
    head = (f"PARTIAL: steps {', '.join(run)} can run; the others did not pass." if run else
            "NOT ALLOWED: no step of this plan can run on its own.")
    return head + "\n" + "\n".join(lines)
