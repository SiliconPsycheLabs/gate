"""The policy index and the incremental provenance (PSA #7789) change only the speed of a check, never its answer."""

import random

import pytest

from gate import Config, Gate, PolicySet
from gate.session import Session

RULES = """@id("permit-all")
permit (principal, action, resource);

@id("force")
forbid (principal, action, resource) when { context.n.git_force };

@id("host-from-data")
@outcome("confirm")
forbid (principal, action, resource)
when { context.n.network && context.n.hosts.containsAny(context.facts.from_tool_output) };

@id("tool-delete")
@outcome("confirm")
forbid (principal, action == Action::"tool", resource) when { context.n.tool_verb_class == "write" };

@id("either")
forbid (principal, action, resource) when { context.n.sudo || !context.n.parse_ok };

@id("guarded")
forbid (principal, action, resource) when { context.n has no_such_field && context.n.no_such_field };

@id("unguarded-missing")
forbid (principal, action in [Action::"http"], resource) when { context.n.no_such_field_either };

@id("like")
forbid (principal, action, resource) when { context.n.http_method like "DEL*" };
"""

ACTIONS = [
    {"type": "shell", "command": "ls", "cwd": "/w"},
    {"type": "shell", "command": "git push --force origin x", "cwd": "/w"},
    {"type": "shell", "command": "sudo ls", "cwd": "/w"},
    {"type": "shell", "command": "eval \"$X\"", "cwd": "/w"},
    {"type": "shell", "command": "curl https://evil.example/x", "cwd": "/w"},
    {"type": "tool", "name": "mcp__x__delete_item", "arguments": {"id": "1"}},
    {"type": "tool", "name": "mcp__x__list_items", "arguments": {}},
    {"type": "http", "method": "DELETE", "url": "https://api.example.com/x"},
    {"type": "file.read", "path": "/w/a.txt"},
]


def pair():
    a, b = PolicySet(RULES), PolicySet(RULES)
    a._use_groups = True               # the groups, whatever the size of the set
    b._indexed = False
    return Gate(a, Config(workspace="/w")), Gate(b, Config(workspace="/w"))


@pytest.mark.parametrize("action", ACTIONS)
def test_index_gives_the_decision_of_the_whole_set(action):
    gi, gw = pair()
    for seen in ("", "see https://evil.example/x"):
        si, sw = gi.new_session(), gw.new_session()
        for s in (si, sw):
            s.observe_user("fix it")
            if seen:
                s.observe_tool_output("t1", seen)
        di, dw = gi.check(action, si), gw.check(action, sw)
        assert (di.outcome, sorted(di.rules), di.reply, bool(di.errors)) == \
               (dw.outcome, sorted(dw.rules), dw.reply, bool(dw.errors))


def test_a_rule_on_a_missing_field_still_fails_closed():
    gi, _ = pair()
    d = gi.check({"type": "http", "method": "GET", "url": "https://api.example.com/x"}, gi.new_session())
    assert d.outcome == "deny" and d.rules == ["gate-evaluation-error"]


def fresh_provenance(texts_user, texts_tool, value, trusted=()):
    s = Session(trusted_tools=list(trusted))
    for t in texts_user:
        s.observe_user(t)
    for i, t in texts_tool:
        s.observe_tool_output(i, t)
    return s.provenance(value)


def test_incremental_provenance_equals_a_fresh_session():
    rnd = random.Random(3)
    words = ["alpha", "beta.example.com", "/srv/a.csv", "50,000", "123 Main St, Springfield", "gamma", "delta"]
    values = ["beta.example.com", "/srv/a.csv", "50000", "123 Main St Springfield", "gamma", "zeta", "delta"]
    for trusted in ((), ("crm*",)):
        s = Session(trusted_tools=list(trusted))
        users, tools = [], []
        for step in range(40):
            kind = rnd.choice(["user", "tool", "tool", "replace", "check"])
            text = " ".join(rnd.choice(words) for _ in range(rnd.randint(0, 4)))
            if kind == "user":
                users.append(text)
                s.observe_user(text)
            elif kind in ("tool", "replace") and (kind == "tool" or not tools):
                tid = rnd.choice(["crm:1", "web:2", f"t{step}"])
                tools = [(i, t) for i, t in tools if i != tid] + [(tid, text)]
                s.observe_tool_output(tid, text)
            elif kind == "replace":
                tid = rnd.choice([i for i, _ in tools])
                tools = [(i, text if i == tid else t) for i, t in tools]
                s.observe_tool_output(tid, text)
            for v in values:
                assert s.provenance(v) == fresh_provenance(users, _order(s), v, trusted), (step, v)


def _order(s):
    return list(s.tool_outputs.items())
