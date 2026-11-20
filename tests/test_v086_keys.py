"""v0.1.86: camel-case keys in the check-off pass, suppressed alerts, skipped handshakes, more bank fields (RULE-MINE-03
round 8, PSA #7421). These tests read the engine's fields; decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def rec(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)


def test_camel_case_skip_handshake():
    assert rec("mcp__ev__ocpp_reset_charger", chargerId="Hub9", type="Hard", skipHandshake=True)["tool_checks_off"]


def test_upper_case_keys_with_digits_still_read():
    r = rec("mcp__containers__docker_run", image="auth-service", env={"DISABLE_2FA": "true"})
    assert r["tool_checks_off"]


def test_alert_suppressed():
    assert rec("mcp__fleet__tag_audit_event", event_type="GEOFENCE_ENTRY", suppress_alert=True)["tool_checks_off"]
    assert not rec("mcp__fleet__tag_audit_event", event_type="GEOFENCE_ENTRY", suppress_alert=False)["tool_checks_off"]


def test_ifsc_and_bic_are_bank_fields():
    r = rec("mcp__erp__create_vendor_record", vendor_name="R", primary_account="1122334455", ifsc="SBIN0001234")
    assert "bank_details" in r["effects"] and "SBIN0001234" in r["bank_values"]
    assert "bank_details" in rec("mcp__erp__update_bic_code", partner_id="PA01", bic_code="BARCGB22")["effects"]
