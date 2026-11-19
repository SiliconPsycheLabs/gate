"""The task contract (gate/contract.py): what falls outside it is a fact; a person's approval widens it."""

import pytest

from gate import Config, Gate, PolicySet

RULES = """@id("permit-all")
permit (principal, action, resource);

@id("outside-contract")
@outcome("confirm")
@reason("outside the task contract.")
forbid (principal, action, resource) when { !context.facts.outside_contract.isEmpty() };
"""
CONTRACT = {"tools": ["mcp__crm__*"], "hosts": ["api.example.com", "*.corp.example"],
            "targets": ["anna@example.com"], "paths": ["/work/repo"]}


def gate(contract=CONTRACT):
    return Gate(PolicySet(RULES), Config(workspace="/work/repo", contract=contract))


def check(g, action, s=None):
    s = s or g.new_session()
    return g.check(action, s), s


T = lambda n, **a: {"type": "tool", "name": n, "arguments": a}


@pytest.mark.parametrize("action,inside", [
    (T("mcp__crm__get_contact", id="7"), True),
    (T("mcp__mail__send_email", to="anna@example.com"), False),
    (T("mcp__crm__send_email", to="anna@example.com"), True),
    (T("mcp__crm__send_email", to="drop@evil.example"), False),
    ({"type": "http", "method": "GET", "url": "https://api.example.com/v1/x"}, True),
    ({"type": "http", "method": "GET", "url": "https://eu.corp.example/x"}, True),
    ({"type": "http", "method": "GET", "url": "https://evil.example/x"}, False),
    ({"type": "file.write", "path": "/work/repo/a.txt"}, True),
    ({"type": "file.write", "path": "/srv/other/a.txt"}, False),
    ({"type": "shell", "command": "curl https://api.example.com/x", "cwd": "/work/repo"}, True),
    ({"type": "shell", "command": "curl https://evil.example/x", "cwd": "/work/repo"}, False),
])
def test_outside_the_contract_is_held(action, inside):
    d, _ = check(gate(), action)
    assert (d.outcome == "allow") is inside, d.record["facts"]["outside_contract"]


def test_no_contract_constrains_nothing():
    d, _ = check(gate(None), T("mcp__mail__send_email", to="drop@evil.example"))
    assert d.outcome == "allow" and d.record["facts"]["outside_contract"] == []


def test_a_dimension_left_out_constrains_nothing():
    d, _ = check(gate({"tools": ["mcp__crm__*"]}), {"type": "http", "method": "GET", "url": "https://evil.example/x"})
    assert d.outcome == "allow"


def test_approval_widens_the_contract_for_the_session():
    g = gate()
    a = T("mcp__crm__send_email", to="bob@example.com")
    d, s = check(g, a)
    assert d.outcome == "confirm" and d.record["facts"]["outside_contract"] == ["target:bob@example.com"]
    g.approve(d, s)
    assert check(g, a, s)[0].outcome == "allow"
    assert check(g, T("mcp__crm__send_email", to="carl@example.com"), s)[0].outcome == "confirm"
    assert check(g, a)[0].outcome == "confirm"            # a new session starts from the declared contract


@pytest.mark.parametrize("bad", [{"tool": ["x"]}, {"hosts": "a.com"}, {"hosts": [""]}, ["tools"]])
def test_a_malformed_contract_is_refused(bad):
    with pytest.raises(ValueError):
        gate(bad)
