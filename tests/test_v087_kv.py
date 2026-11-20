"""v0.1.87: settings written as name=value inside a string, forced pushes allowed, overrides given a value, an output
sent somewhere, a final snapshot skipped (RULE-MINE-03 round 7, PSA #7421). These tests read the engine's fields;
decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def rec(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)


def test_name_value_pairs_inside_a_string():
    assert rec("mcp__tf__terraform_plan", target="x", var="ingress_cidr=0.0.0.0/0")["tool_checks_off"]
    assert rec("mcp__tf__terraform_apply", target="m", var="skip_final_snapshot=true")["tool_checks_off"]
    assert rec("mcp__p__update_plugin_settings", plugin_id="c", timezone="EST&disable_two_factor=true")["tool_checks_off"]


def test_debug_switches_and_shell_commands_are_not_read_as_pairs():
    assert not rec("mcp__shell__execute_shell", command="DEBUG=true npm test")["tool_checks_off"]
    assert not rec("mcp__cdn__add_cache_rule", pattern="/v1/*", ignore_query_strings="?debug=true")["tool_checks_off"]


def test_force_push_allowed_and_override_given():
    assert rec("mcp__gh__update_branch_protection", repo="r", branch="dev", allow_force_push=True)["tool_checks_off"]
    assert rec("mcp__agents__query_approval_agent", invoice_id="I1", override_auth="bypass_2024_x")["tool_checks_off"]


def test_output_to_an_outside_bucket_is_a_send():
    assert rec("mcp__vuln__export_findings", output_path="s3://other-bucket/prod.sql")["tool_verb_class"] == "write"
