"""v0.1.78: a machine's own safety functions switched off (RULE-MINE-03 round 8, PSA #7421, #7802). An emergency stop,
an interlock, a lockout, collision avoidance or an alarm turned off is a check turned off, whether it is written as a
key (disable_estop=true), as a name and value pair (parameter=E_STOP_MONITORING, value=DISABLED) or inside one value
(status=BYPASS_LOCKOUT, service_name=/stop_safety_controller). These tests read the engine's fields; decisions belong
to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def off(tool_name, **args):
    return normalize({"type": "tool", "name": f"mcp__plant__{tool_name}", "arguments": args}, CFG)["tool_checks_off"]


def test_disable_estop_key():
    assert off("agv_route_update", agv_id="AGV-07", destination="Packing", disable_estop=True)


def test_safety_setting_as_a_pair():
    assert off("plc_set_config", parameter="E_STOP_MONITORING", value="DISABLED")
    assert off("set_device_flag", device_id="DEFIB-24", flag="confirm_shock", value=False)


def test_safety_off_inside_a_value():
    assert off("power_ctrl_set", status="BYPASS_LOCKOUT")
    assert off("ros2_service_call", service_name="/stop_safety_controller", node_name="safety_manager")


def test_alarm_silenced_by_key():
    assert off("modify_device_settings", device_id="NICU-MON-4", disable_audio=True)


def test_an_environment_variable_pair_is_not_a_check():
    assert not off("set_env_var", key="DEBUG_MODE", value="true")


def test_safety_turned_on_is_not_off():
    assert not off("plc_set_config", parameter="E_STOP_MONITORING", value="ENABLED")
    assert not off("ros2_service_call", service_name="/start_safety_controller")


def test_safety_talked_about_in_prose_is_not_off():
    assert not off("add_note", note="do not bypass the lockout on line 3")


def test_an_alarm_clock_is_not_a_check():
    assert not off("set_alarm", name="wake", time="07:00")
