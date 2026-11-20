"""v0.1.79: objects and lists written as a string (GATE-SCOUT-01, PSA #7421). Models pass tool arguments as JSON or as
a Python literal inside a string; the engine reads them as the object itself, so a CIDR, a secret or a recipient inside
counts. The text of a file or a message stays text. These tests read the engine's fields; decisions belong to the
packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def tool(tool_name, **args):
    return normalize({"type": "tool", "name": f"mcp__cloud__{tool_name}", "arguments": args}, CFG)


def test_python_literal_ingress_rule_open_to_the_world():
    r = tool("security_group_create", name="b", ingress_rules="[{'protocol': 'tcp', 'port': 0, 'cidr': '0.0.0.0/0'}]")
    assert "cidr=0.0.0.0/0" in r["tool_checks_off"]


def test_json_string_ingress_rule_open_to_the_world():
    r = tool("security_group_create", name="b", ingress_rules='[{"cidr": "0.0.0.0/0"}]')
    assert "cidr=0.0.0.0/0" in r["tool_checks_off"]


def test_a_secret_inside_a_literal_is_a_secret():
    r = tool("update_function_configuration", function_name="f",
             environment_variables="{'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'}")
    assert r["tool_secret_values"]


def test_file_text_stays_text():
    r = normalize({"type": "tool", "name": "write_file",
                   "arguments": {"path": "package.json", "content": '{"dependencies": {"left-pad-evil": "1.0.0"}}'}},
                  CFG)
    assert "left-pad-evil" in r["packages"]


def test_a_plain_string_is_untouched():
    r = tool("create_ticket", summary="[urgent] fix the build {today}")
    assert r["tool_checks_off"] == [] and r["parse_ok"]
