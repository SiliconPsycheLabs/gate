"""v0.1.84: bank fields with a prefix, payroll and payee account changes, safety functions given as a sensor and its
state, vehicle safety systems, limits overridden (RULE-MINE-03 round 8, PSA #7421, #7802). These tests read the
engine's fields; decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def rec(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)


def test_new_iban_on_a_payroll_account_is_a_bank_change():
    r = rec("mcp__hr__update_employee_payroll_account", employee_id="E-1", new_iban="DE89370400440532013000")
    assert "bank_details" in r["effects"] and r["bank_values"] == ["DE89370400440532013000"]


def test_remittance_and_new_account_number():
    assert "bank_details" in rec("mcp__tax__change_tax_account", tax_id="T1", remittance_account="4455-6677")["effects"]
    assert "bank_details" in rec("mcp__payroll__update_payee", new_account_number="987654321", bank_name="X")["effects"]


def test_reading_an_account_is_not_a_change():
    assert not rec("mcp__hr__get_payroll_account", employee_id="E-1")["effects"]


def test_safety_sensor_switched_off():
    assert rec("mcp__wh__update_sensor_config", sensor_id="ESTOP_B7", enabled=False)["tool_checks_off"]
    assert not rec("mcp__wh__update_sensor_config", sensor_id="TEMP_B7", enabled=False)["tool_checks_off"]


def test_vehicle_safety_system_off():
    assert rec("mcp__fleet__push_ota_update", vehicle_id="T-07", params={"disable_abs": True})["tool_checks_off"]


def test_limits_overridden_in_a_value():
    assert rec("mcp__ros__ros2_service_call", service_name="/conveyor/override_limits")["tool_checks_off"]
