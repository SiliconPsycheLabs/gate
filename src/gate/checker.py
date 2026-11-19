"""Evaluate an action record against Cedar policies and return a deterministic decision."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

import cedarpy

ALLOW, DENY, CONFIRM = "allow", "deny", "confirm"
# Up to this many policies one call on the whole parsed set is the fastest check; above it, the indexed groups are
# (GATE-PERF-01, PSA #7789: about 2 ms for 1,000 rules either way, the whole set growing linearly beyond).
GROUP_ABOVE = 2000
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
        self._static: dict[str, dict] = parsed.get("staticPolicies", {}) or {}
        self.rules: dict[str, Rule] = {}
        for pid, pol in self._static.items():
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
        # Index (PSA #7789): the policies are split, once, into groups that are each parsed once: the policies with
        # no known first condition, by action type, and the policies whose first condition needs a given fact of
        # the record ("network is true", "hosts is not empty"). A check evaluates only the groups whose fact holds
        # on its record, and combines their answers as Cedar combines policies (any forbid that applies denies; else
        # any permit that applies allows; else nothing allows). A group is left out only when its fact is false on
        # the record without error, so the answer is the one Cedar gives on the whole set. The index reads Cedar's
        # own parse of each condition.
        self._indexed = not (parsed.get("templates") or parsed.get("templateLinks"))
        self._use_groups = self._indexed and len(self._static) > GROUP_ABOVE
        self._scope: dict[str, frozenset | None] = {pid: _action_scope(pol) for pid, pol in self._static.items()}
        self._always: list[str] = []
        self._atoms: dict[tuple, list[str]] = {}
        for pid, pol in self._static.items():
            need = _first_condition_atoms(pol)
            if need is None:
                self._always.append(pid)
            else:
                for a in need:
                    self._atoms.setdefault(a, []).append(pid)
        self._groups: dict = {}
        self._full = None

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
        if not (self._indexed and self._use_groups):
            if self._full is None:
                self._full = cedarpy.PolicySet.from_str(self.text)
            res = cedarpy.is_authorized(request, self._full, entities)
            allowed, found, errors = res.decision == cedarpy.Decision.Allow, set(res.diagnostics.reasons), \
                list(res.diagnostics.errors)
        else:
            allowed, found, errors = self._evaluate_groups(request, action_type, context, entities)
        if errors:
            # A policy that cannot be evaluated is never skipped: fail closed.
            return Decision(DENY, ["gate-evaluation-error"],
                            "DENIED by rule gate-evaluation-error: a rule could not be evaluated on this action.",
                            errors=errors)
        # Cedar reports the deciding policies in no fixed order; sort by rule id so the same input gives the same
        # list every time, not only the same outcome and reply.
        reasons = sorted((self.rules[p] for p in found if p in self.rules), key=lambda r: r.rule_id)
        forbids = [r for r in reasons if r.effect == "forbid"]
        if allowed and not forbids:
            return Decision(ALLOW, [r.rule_id for r in reasons], "ALLOWED")
        if not forbids:
            return Decision(DENY, ["default-deny"],
                            "DENIED by rule default-deny: no rule allows this action.")
        denying = [r for r in forbids if r.outcome == DENY]
        if denying:
            return Decision(DENY, [r.rule_id for r in forbids], _reply("DENIED", denying))
        return Decision(CONFIRM, [r.rule_id for r in forbids],
                        _reply("HELD", forbids) + " It has not been run: a person must approve it.")


    def _group(self, key: tuple):
        ps = self._groups.get(key)
        if ps is None:
            if key[0] == "always":
                action_type = key[1]
                pids = [p for p in self._always if self._scope[p] is None or action_type in self._scope[p]]
            else:
                atom, action_type = key[1], key[2]
                pids = [p for p in self._atoms[atom] if self._scope[p] is None or action_type in self._scope[p]]
            if not pids:
                ps = False
            else:
                body = {"staticPolicies": {p: self._static[p] for p in pids}, "templates": {}, "templateLinks": []}
                ps = cedarpy.PolicySet.from_json_str(json.dumps(body))
            self._groups[key] = ps
        return ps

    def _evaluate_groups(self, request: dict, action_type: str, context: dict, entities: list):
        keys = [("always", action_type)] + [("atom", a, action_type) for a in sorted(self._atoms, key=repr)
                                             if _atom_holds(a, context)]
        handle = None
        allowed, found, errors = False, set(), []
        for key in keys:
            ps = self._group(key)
            if ps is False:
                continue
            if handle is None:
                handle = cedarpy.Entities.from_json_str(json.dumps(entities))
            res = cedarpy.is_authorized(request, ps, handle)
            if res.decision == cedarpy.Decision.Allow:
                allowed = True
            found.update(res.diagnostics.reasons)
            for err in res.diagnostics.errors:
                if err not in errors:
                    errors.append(err)
        return allowed, found, sorted(errors)


# ---- the index: what a policy needs before it can apply ----------------------------------------------------------

def _action_scope(pol: dict) -> frozenset | None:
    """The action types a policy is scoped to; None means every action."""
    a = pol.get("action") or {}
    if a.get("op") == "==" and (a.get("entity") or {}).get("type") == "Action":
        return frozenset([a["entity"]["id"]])
    if a.get("op") == "in":
        ents = a.get("entities") if "entities" in a else [a.get("entity")]
        if ents and all(isinstance(e, dict) and e.get("type") == "Action" for e in ents):
            return frozenset(e["id"] for e in ents)
    return None


def _path(e) -> tuple | None:
    """`context.a.b` as ("a", "b"); None for anything else."""
    names = []
    while isinstance(e, dict) and "." in e:
        names.append(e["."]["attr"])
        e = e["."]["left"]
    if e == {"Var": "context"} and names:
        return tuple(reversed(names))
    return None


def _atoms(e) -> frozenset | None:
    """Atoms of which at least one must hold for the expression to be true, each one false on a record only when the
    expression is false there without an error. None when no such set is known."""
    if not isinstance(e, dict) or len(e) != 1:
        return None
    op, x = next(iter(e.items()))
    if op == ".":
        p = _path(e)
        return frozenset([("true", p)]) if p else None
    if op == "!":
        p = _path(x.get("arg"))
        if p:
            return frozenset([("false", p)])
        inner = x.get("arg")
        if isinstance(inner, dict) and "isEmpty" in inner:
            p = _path(inner["isEmpty"].get("arg"))
            return frozenset([("nonempty", p)]) if p else None
        return None
    if op in ("contains", "containsAny"):
        # the argument is evaluated too: it must be a literal or an attribute that exists, or Cedar may report an
        # error that leaving the policy out would hide
        p, arg = _path(x.get("left")), x.get("right")
        if not p:
            return None
        if _literal(arg):
            return frozenset([("nonempty", p)])
        q = _path(arg)
        return frozenset([("nonempty", p, q)]) if q else None
    if op == "==":
        for a, b in ((x.get("left"), x.get("right")), (x.get("right"), x.get("left"))):
            p = _path(a)
            if p and isinstance(b, dict) and "Value" in b and isinstance(b["Value"], (str, bool, int)):
                return frozenset([("eq", p, b["Value"])])
        return None
    if op == "has":
        p = _path(x.get("left"))
        return frozenset([("has", p, x.get("attr"))]) if p else None
    if op == "&&":
        return _atoms(x.get("left"))
    if op == "||":
        left, right = _atoms(x.get("left")), _atoms(x.get("right"))
        return left | right if left is not None and right is not None else None
    return None


def _literal(e) -> bool:
    if not isinstance(e, dict) or len(e) != 1:
        return False
    op, x = next(iter(e.items()))
    if op == "Value":
        return True
    if op == "Set":
        return all(_literal(i) for i in x)
    return False


def _first_condition_atoms(pol: dict) -> frozenset | None:
    conds = pol.get("conditions") or []
    if not conds or conds[0].get("kind") != "when":
        return None
    return _atoms(conds[0].get("body"))


_MISSING = object()


def _resolve(context: dict, path: tuple):
    v = context
    for name in path:
        if not isinstance(v, dict) or name not in v:
            return _MISSING
        v = v[name]
    return v


def _atom_holds(atom: tuple, context: dict) -> bool:
    """False only when the atom is certainly false on this context; a missing attribute or an unexpected type
    counts as holding, so Cedar itself evaluates (and reports any error)."""
    kind, path = atom[0], atom[1]
    v = _resolve(context, path)
    if v is _MISSING:
        return True
    if kind == "true":
        return v is not False
    if kind == "false":
        return v is not True
    if kind == "nonempty":
        if len(atom) > 2 and _resolve(context, atom[2]) is _MISSING:
            return True
        return not isinstance(v, list) or len(v) > 0
    if kind == "eq":
        want = atom[2]
        if type(v) is not type(want):
            return True
        return v == want
    if kind == "has":
        return not isinstance(v, dict) or atom[2] in v
    return True


def _reply(verb: str, rules: list[Rule]) -> str:
    parts = []
    for r in sorted(rules, key=lambda x: x.rule_id):
        parts.append(f"{verb} by rule {r.rule_id}" + (f": {r.reason}" if r.reason else "."))
    return " ".join(p if p.endswith(".") else p + "." for p in parts)


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')
