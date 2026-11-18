"""Evaluate an action record against Cedar policies and return a deterministic decision."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

import cedarpy

ALLOW, DENY, CONFIRM = "allow", "deny", "confirm"
KNOWN_ACTIONS = ["shell", "file.read", "file.write", "file.delete", "http", "git", "package.install", "service", "tool"]


@dataclass
class Rule:
    policy_id: str
    rule_id: str
    effect: str
    outcome: str
    reason: str


@dataclass
class Decision:
    outcome: str
    rules: list[str]
    reply: str
    record: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.outcome == ALLOW

    def to_dict(self) -> dict:
        return asdict(self)


class PolicySet:
    """A set of Cedar policies with the gate's annotations.

    Annotations read by the gate:
      @id("rule-name")          stable rule id, used in replies and logs (required on forbid policies)
      @outcome("confirm")       on a forbid: hold for a person instead of denying
      @reason("one line")       the fixed text the model receives
    """

    def __init__(self, text: str):
        self.text = text
        parsed = json.loads(cedarpy.policies_to_json_str(text))
        self.rules: dict[str, Rule] = {}
        for pid, pol in parsed.get("staticPolicies", {}).items():
            ann = pol.get("annotations", {}) or {}
            effect = pol.get("effect", "permit")
            outcome = ann.get("outcome", DENY if effect == "forbid" else ALLOW)
            if outcome not in (ALLOW, DENY, CONFIRM):
                raise ValueError(f"policy {ann.get('id', pid)}: unknown outcome {outcome!r}")
            self.rules[pid] = Rule(pid, ann.get("id", pid), effect, outcome, ann.get("reason", ""))
        ids = [r.rule_id for r in self.rules.values()]
        dup = {i for i in ids if ids.count(i) > 1}
        if dup:
            raise ValueError(f"duplicate rule ids: {sorted(dup)}")

    @classmethod
    def from_paths(cls, paths: list[str | Path]) -> "PolicySet":
        texts = []
        for p in paths:
            p = Path(p)
            files = sorted(p.glob("*.cedar")) if p.is_dir() else [p]
            for f in files:
                texts.append(f"// file: {f.name}\n" + f.read_text())
        return cls("\n".join(texts))

    def evaluate(self, action_type: str, agent: str, context: dict, agent_attrs: dict | None = None) -> Decision:
        request = {
            "principal": f'Agent::"{_esc(agent)}"',
            "action": f'Action::"{_esc(action_type)}"',
            "resource": f'Target::"{_esc(action_type)}"',
            "context": context,
        }
        entities = [{"uid": {"type": "Agent", "id": agent}, "attrs": agent_attrs or {}, "parents": []}]
        res = cedarpy.is_authorized(request, self.text, entities)
        errors = list(res.diagnostics.errors)
        if errors:
            # A policy that cannot be evaluated is never skipped: fail closed.
            return Decision(DENY, ["gate-evaluation-error"],
                            "DENIED by rule gate-evaluation-error: a rule could not be evaluated on this action.",
                            errors=errors)
        # Cedar reports the deciding policies in no fixed order; sort by rule id so the same input gives the same
        # list every time, not only the same outcome and reply.
        reasons = sorted((self.rules[p] for p in res.diagnostics.reasons if p in self.rules), key=lambda r: r.rule_id)
        if res.decision == cedarpy.Decision.Allow:
            return Decision(ALLOW, [r.rule_id for r in reasons], "ALLOWED")
        forbids = [r for r in reasons if r.effect == "forbid"]
        if not forbids:
            return Decision(DENY, ["default-deny"],
                            "DENIED by rule default-deny: no rule allows this action.")
        denying = [r for r in forbids if r.outcome == DENY]
        if denying:
            return Decision(DENY, [r.rule_id for r in forbids], _reply("DENIED", denying))
        return Decision(CONFIRM, [r.rule_id for r in forbids],
                        _reply("HELD", forbids) + " It has not been run: a person must approve it.")


def _reply(verb: str, rules: list[Rule]) -> str:
    parts = []
    for r in sorted(rules, key=lambda x: x.rule_id):
        parts.append(f"{verb} by rule {r.rule_id}" + (f": {r.reason}" if r.reason else "."))
    return " ".join(p if p.endswith(".") else p + "." for p in parts)


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')
