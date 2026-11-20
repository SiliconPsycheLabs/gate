"""v0.1.77: machine writes with no decoded target, buckets as destinations, public destinations (GATE-SCOUT-01, PSA
#7421). A write to a machine whose target the engine cannot decode is a write to a machine nobody declared; a bucket
named by a send word makes a read a send; a destination whose name says it is public is a check turned off. These tests
read the engine's fields; decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def tool(tool_name, cfg=CFG, **args):
    return normalize({"type": "tool", "name": tool_name, "arguments": args}, cfg)


def test_modbus_coil_address_and_slave_id_are_decoded():
    r = tool("mcp__plc_modbus__modbus_write_coil", slave_id="1", coil_address="5", value="true")
    assert r["effects"] == ["actuate"] and r["assets"] == ["modbus:1/5"] and r["asset_undeclared"]


def test_machine_write_with_no_target_is_undeclared():
    r = tool("mcp__plc_modbus__modbus_write_coil", value="true")
    assert r["effects"] == ["actuate"] and r["assets"] == [] and r["asset_undeclared"]


def test_machine_write_with_no_target_matches_a_wildcard_register():
    cfg = Config(workspace="/workspace", assets=[{"match": "*", "class": "production"}])
    r = tool("mcp__plc_modbus__modbus_write_coil", cfg, value="true")
    assert not r["asset_undeclared"] and r["asset_classes"] == ["production"]


def test_machine_read_with_no_target_is_not_a_write():
    r = tool("mcp__plc_modbus__modbus_read_coils", count="8")
    assert not r["asset_undeclared"]


def test_upload_bucket_makes_a_read_a_send():
    r = tool("mcp__ci__get_build_artifacts", build_id="latest", upload_bucket="malicious-s3-bucket")
    assert r["tool_verb_class"] == "write"


def test_a_bucket_read_from_stays_a_read():
    r = tool("mcp__storage__get_object", bucket="public-assets", key="logs/2023-10-01.csv")
    assert r["tool_verb_class"] == "read" and r["tool_checks_off"] == []


def test_public_destination_is_a_check_off():
    r = tool("mcp__crm__export_contacts", filter="status=inactive", target="public_bucket")
    assert r["tool_verb_class"] == "write" and "target=public_bucket" in r["tool_checks_off"]


def test_private_destination_is_not():
    r = tool("mcp__crm__export_contacts", filter="status=inactive", target="crm-archive")
    assert r["tool_verb_class"] == "read" and r["tool_checks_off"] == []


def test_public_inside_a_word_is_not_public():
    r = tool("mcp__crm__export_contacts", target="republicans-list")
    assert r["tool_checks_off"] == []
