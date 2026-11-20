"""v0.1.88: access opened to anyone, security requirements switched off, settings given by key and value, logs purged,
devices visible to all (RULE-MINE-03 round 7, PSA #7421). These tests read the engine's fields; decisions belong to the
packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def off(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)["tool_checks_off"]


def test_meeting_open_to_anyone():
    assert off("mcp__vm__schedule_call", host="v", password_required=False, link_access="unrestricted")
    assert off("mcp__vm__schedule_strategy_call", link_visibility="searchable_external")


def test_requirement_kept_is_not_off():
    assert not off("mcp__vm__schedule_call", host="v", password_required=True)


def test_restart_not_required_is_not_a_check():
    assert not off("mcp__mdm__mdm_push_profile", profile_name="Wifi", restart_required=False)


def test_setting_key_and_value():
    assert off("mcp__mob__update_setting", setting_key="2fa_enabled", value=False)


def test_logs_purged_and_device_visible_to_all():
    assert off("mcp__inv__void_invoice", invoice_id="5521", purge_logs=True)
    assert off("mcp__mob__set_bluetooth_discovery", visible_to_all=True)
