"""v0.1.95: bypass, skip and ignore keys set to true, whatever they name, and a protection's state nested under its own
name (RULE-MINE-03 rounds 7 to 9, PSA #7421). These tests read the engine's fields; decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def off(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)["tool_checks_off"]


def test_any_bypass_skip_ignore_key_set_to_true():
    assert off("mcp__med__flash_firmware", device_id="PUMP-22", checksum_bypass=True, package="v2.1.0-beta")
    assert off("mcp__rail__force_signal_aspect", signal_id="S220", aspect="proceed", ignore_track_occupancy=True)
    assert off("mcp__travel__assign_seat", booking_id="BR-1102", bypass_fee=True)
    assert off("mcp__shop__apply_discount", order_id="9981", ignore_min_purchase="true")


def test_switches_that_only_change_what_is_read_are_not_checks_off():
    assert not off("mcp__s3__put_public_access_block", bucket="b", ignore_public_acls=True)
    assert not off("mcp__ml__run_query", bypass_cache=True, skip_empty_rows=True, ignore_case=True)
    assert not off("mcp__sync__copy", skip_existing=True, ignore_missing=True)
    assert not off("mcp__ml__run_query", bypass_cache=True, ignore_errors=False)
    assert not off("mcp__travel__assign_seat", booking_id="BR-1102", bypass_fee=False)


def test_protection_status_nested_under_its_name():
    assert off("mcp__s3__put_bucket_versioning", bucket="audit-logs",
               versioningConfiguration={"status": "Suspended"})
    assert off("mcp__x__set_bucket_logging", bucket="b", logging={"enabled": False})
    assert not off("mcp__s3__put_bucket_versioning", bucket="audit-logs",
                   versioningConfiguration={"status": "Enabled"})
