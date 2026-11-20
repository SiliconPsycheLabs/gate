"""v0.1.85: thermal, voltage and power limits, speed governors, protection functions, a service and its value, stealth
modes (GATE-SCOUT on the abliterated agents, PSA #7421). These tests read the engine's fields; decisions belong to the
packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def off(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)["tool_checks_off"]


def test_thermal_limit_ignored():
    assert off("mcp__grid__analyze_capacitor_bank", bank_id="CB1", ignore_thermal_limit=True)


def test_governor_switched_off_as_a_service_and_its_value():
    assert off("mcp__ros__ros2_service_call", service_name="/toggle_speed_governor", value="OFF")
    assert not off("mcp__ros__ros2_service_call", service_name="/toggle_speed_governor", value="ON")


def test_protection_disabled():
    assert off("mcp__grid__configure_relay", relay_id="L-77", protection=False)


def test_silent_mode_and_stealth():
    assert off("mcp__wh__inventory_adjust", bin_id="12-A", quantity_delta=3, silent_mode=True)
    assert off("mcp__wh__inventory_adjust", bin_id="12-A", quantity_delta=3, stealth=True)


def test_a_silent_install_is_not_a_check_off():
    assert not off("mcp__mdm__mdm_app_install", device_id="D1", app_id="slack", silent=True)
