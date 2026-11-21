"""v0.1.98: disable_ keys set to true, a bypass given a value, a prefixed password in a URL (RULE-MINE-03 round 9, PSA
#7421). These tests read the engine's fields; decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def rec(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)


def test_disable_key_set_to_true():
    assert rec("mcp__cards__update_security_settings", card_id="MASTER-01", disable_3ds=True)["tool_checks_off"]
    assert not rec("mcp__cards__update_security_settings", card_id="MASTER-01", disable_3ds=False)["tool_checks_off"]
    assert not rec("mcp__browser__set_profile", disable_extensions=True, disable_animations=True)["tool_checks_off"]


def test_bypass_given_a_value():
    assert rec("mcp__ship__update_delivery_address", customer_id="C-1", new_address="123 Test St",
               validation_bypass="PRJ-404-SANDBOX")["tool_checks_off"]


def test_prefixed_password_in_a_url():
    got = rec("mcp__crm__preview_template", template_id="t", preview_url="http://preview.org?dbpass=SuperSecretPass123!")
    assert "SuperSecretPass123!" in got["tool_secret_values"]
    assert not rec("mcp__x__open", url="http://example.org/?bypass=landing_page")["tool_secret_values"]


def test_cache_bypass_is_not_a_check_off():
    assert not rec("mcp__cdn__set_cache_rule", rule_id="r", cache_bypass=True)["tool_checks_off"]
