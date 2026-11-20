"""v0.1.91: a tool is read by what its owner declared it does, not by the words of its name (Config.tool_effects)."""

import pytest

from gate import Gate
from gate.checker import PolicySet
from gate.config import TOOL_EFFECTS, Config
from gate.normalize import normalize
from gate.schema import context_shape

T = lambda n, **a: {"type": "tool", "name": n, "arguments": a}
CFG = Config(workspace="/w/repo", tool_effects={
    "pay": "money", "remit": ["money"], "op_17": ["money", "send"],
    "mcp__crm__*": "read", "mcp__crm__delete_*": "delete",
    "fetch_and_forward": "send", "lookup": "read", "typo": ["mony"], "silent": []})


def rec(name, **args):
    return normalize(T(name, **args), CFG)


@pytest.mark.parametrize("name", ["pay", "remit", "op_17"])
def test_the_declaration_is_read_whatever_the_tool_is_called(name):
    r = rec(name, a="DE89370400440532013000", b=1200)
    assert "money" in r["declared_effects"] and not r["effect_undeclared"]
    assert r["tool_verb_class"] == "write"


def test_a_tool_declared_to_read_is_a_read_and_one_that_reads_by_name_only_is_not():
    assert rec("lookup", q="x")["tool_verb_class"] == "read"
    # the name starts with a reading verb, the owner said it sends: it is not a read
    r = rec("fetch_and_forward", to="k.brandt@northwind-supplies.example")
    assert r["declared_effects"] == ["send"] and r["tool_verb_class"] == "write"
    assert "k.brandt@northwind-supplies.example" in r["tool_arg_values"]
    # nobody declared it: its reading name does not make it a read while declarations are in force
    r = rec("get_everything", q="x")
    assert r["effect_undeclared"] and r["declared_effects"] == [] and r["tool_verb_class"] == "write"


def test_several_patterns_add_up_and_the_server_prefix_can_be_left_out():
    assert rec("mcp__crm__get_customer", id="7")["declared_effects"] == ["read"]
    assert rec("mcp__crm__delete_customer", id="7")["declared_effects"] == ["delete", "read"]
    assert rec("mcp__crm__delete_customer", id="7")["tool_verb_class"] == "write"
    assert normalize(T("mcp__bank__pay", iban="x"), CFG)["declared_effects"] == ["money"]


@pytest.mark.parametrize("name", ["typo", "silent", "never_listed"])
def test_an_unreadable_or_missing_declaration_is_no_declaration(name):
    r = rec(name, a=1)
    assert r["effect_undeclared"] and r["declared_effects"] == []


def test_nothing_changes_for_an_owner_who_declared_nothing():
    plain = Config(workspace="/w/repo")
    for name in ("pay", "get_everything", "op_17"):
        r = normalize(T(name, a=1), plain)
        assert r["declared_effects"] == [] and not r["effect_undeclared"]
    assert normalize(T("get_everything", a=1), plain)["tool_verb_class"] == "read"
    assert not plain.to_context()["effects_declared"] and CFG.to_context()["effects_declared"]
    # only tool calls are named by their owner; a command is read as before
    assert not normalize({"type": "shell", "command": "ls"}, CFG)["effect_undeclared"]


def test_the_fields_are_in_the_rule_schema_and_a_rule_can_read_them():
    shape = context_shape()["attributes"]
    assert shape["n"]["attributes"]["declared_effects"] == {"type": "Set", "element": {"type": "String"}}
    assert shape["n"]["attributes"]["effect_undeclared"] == {"type": "Boolean"}
    assert shape["config"]["attributes"]["effects_declared"] == {"type": "Boolean"}
    assert len(TOOL_EFFECTS) == len(set(TOOL_EFFECTS)) == 10
    rules = '''
    @id("known") permit (principal, action, resource);
    @id("money") @outcome("confirm") @reason("declared to move money")
    forbid (principal, action == Action::"tool", resource) when { context.n.declared_effects.contains("money") };
    @id("unknown") @outcome("confirm") @reason("nobody declared what it does")
    forbid (principal, action == Action::"tool", resource) when { context.n.effect_undeclared };
    '''
    g = Gate(PolicySet(rules), CFG)
    assert g.check(T("op_17", a=1)).outcome == "confirm" and g.check(T("op_17", a=1)).rules == ["money"]
    assert g.check(T("never_listed", a=1)).rules == ["unknown"]
    assert g.check(T("lookup", q="x")).outcome == "allow"
