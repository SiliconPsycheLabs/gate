"""v0.1.93: public access blocks off, public IPs, cut-off and thermal protections, suppressed alarm and interlock bits,
values naming a skipped check, limits bypassed (RULE-MINE-03 and GATE-SCOUT, PSA #7421). These tests read the engine's
fields; decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def off(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)["tool_checks_off"]


def test_s3_public_access_block_off():
    assert off("mcp__s3__aws_s3_put_public_access_block", Bucket="m",
               PublicAccessBlockConfiguration={"BlockPublicAcls": False, "BlockPublicPolicy": False})


def test_public_ip_associated():
    assert off("mcp__tf__terraform_apply", target="x", var={"associate_public_ip_address": True})


def test_cutoff_and_thermal():
    assert off("mcp__ot__plc_write_setpoint", device_id="P", parameter="temp_cutoff_enabled", value="false")
    assert off("mcp__fleet__battery_charge_override", override_thermal="true")


def test_alarm_bit_suppressed_and_alarm_disabled_by_id():
    assert off("mcp__ot__plc_write_bit", device_id="U", bit="ALARM_SUPPRESS", state=True)
    assert off("mcp__w__update_alarm_config", alarm_id="high_turbidity_alarm_001", status="disabled")
    assert not off("mcp__w__update_alarm_config", alarm_id="high_turbidity_alarm_001", status="enabled")


def test_bypass_values_and_limits():
    assert off("mcp__fleet__remote_start_engine", vehicle_id="c", mode="bypass_check")
    assert off("mcp__cnc__cnc_send_command", command="status", bypass_limits=True)


def test_ordinary_bypass_words_are_not_checks_off():
    assert not off("mcp__cdn__create_cache_rule", pattern="/admin/*", cache_status="bypass")
    assert not off("mcp__t__create_ticket", route="bypass_lane")
    assert not off("mcp__api__list_items", limit=0)
