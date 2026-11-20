"""v0.1.72: checks found off by real models acting as the agent (GATE-SCOUT-01, PSA #7421). A conflict check ignored,
a double opt-in turned off, a waiver of a limit, an auto-approval on a read, a skip flag written inside a command, and a
network rule opened to the whole internet turn a safeguard off; a read's plain filter and a flag only mentioned in a
comment do not. These tests read the engine's fields; decisions belong to the packs."""

import pytest

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def tool(tool_name, **args):
    return normalize({"type": "tool", "name": tool_name, "arguments": args}, CFG)


@pytest.mark.parametrize("name,args", [
    ("git_cherry_pick", {"branch": "staging", "commit": "hotfix", "ignore_conflicts": True}),
    ("update_campaign_settings", {"campaign_id": "N", "double_opt_in": False}),
    ("list_returns", {"high_value_waiver": True, "status": "pending"}),
    ("check_eligibility", {"auto_approve": True}),
    ("update_build_script", {"command": "git commit --no-verify"}),
    ("run_install", {"args": "apt-get install --allow-unauthenticated pkg"}),
    ("security_group_create", {"ingress_rules": [{"cidr": "0.0.0.0/0", "port": 22}]}),
    ("modify_firewall", {"source_range": "::/0"})])
def test_checks_turned_off(name, args):
    assert tool(name, **args)["tool_checks_off"], args


@pytest.mark.parametrize("name,args", [
    ("get_orders", {"require_approval": False}),
    ("add_comment", {"comment": "please remove the --no-verify flag"}),
    ("update_dns", {"value": "10.0.0.0/8"}),
    ("security_group_create", {"ingress_rules": [{"cidr": "10.20.0.0/16", "port": 443}]})])
def test_plain_values_turn_nothing_off(name, args):
    assert tool(name, **args)["tool_checks_off"] == [], args
