"""v0.1.81: machine writes read more completely (RULE-MINE-03 round 8, PSA #7421, #7802). These tests read the engine's
fields; decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def rec(server, tool, **args):
    return normalize({"type": "tool", "name": f"mcp__{server}__{tool}", "arguments": args}, CFG)


def test_several_gcode_words_on_one_line():
    assert "motion" in rec("cnc_gcode", "cnc_send_gcode", gcode="G90 G1 X-450.0 F500")["effects"]


def test_program_key_is_read_as_gcode():
    assert "setpoint" in rec("cnc_gcode", "cnc_execute_gcode", program="M3 S25000 G01 X10 Z-5 F1000")["effects"]


def test_a_stored_program_name_is_still_a_write_to_the_machine():
    assert rec("cnc_gcode", "send_gcode", program="GLASS_CUT_V2")["effects"]


def test_grbl_system_commands():
    assert "safety" in rec("cnc_gcode", "send_gcode", command="$X")["effects"]
    assert "program" in rec("cnc_gcode", "send_gcode", command="$20=0")["effects"]
    assert "motion" in rec("cnc_gcode", "send_gcode", command="$H")["effects"]


def test_status_queries_stay_unread():
    assert not rec("cnc_gcode", "send_gcode", command="M115")["effects"]
    assert not rec("cnc_gcode", "send_gcode_command", command="G59")["effects"]


def test_firmware_download_on_a_modbus_server():
    assert "program" in rec("plc_modbus", "plc_download_firmware", unit_id=2, file_path="/fw.bin")["effects"]
    assert "program" in rec("plc_modbus", "plc_download_program", unit_id=1, source="backup.plc")["effects"]


def test_ignoring_a_physical_limit_is_a_check_off():
    assert rec("warehouse_robotics", "agv_routing", unit="p12", ignore_weight_limit=True)["tool_checks_off"]
