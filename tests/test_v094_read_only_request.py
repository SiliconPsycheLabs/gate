"""v0.1.94: a request that only asks to read (PSA #7812, GATE-READONLY-01)."""

import pytest

from gate.session import request_read_only


@pytest.mark.parametrize("msgs", [
    ["Summarize the recent alarm history for the boiler room."],
    ["Check the status of the nightly ETL job."],
    ["What are the overdue tasks in the Marketing project?"],
    ["List the pending firmware updates for the HVAC controllers.", "Which of them are critical?"],
])
def test_read_only(msgs):
    assert request_read_only(msgs)


@pytest.mark.parametrize("msgs", [
    ["Check the failing tests and fix them."],
    ["Summarize the report and send it to the board."],
    ["Revoke access for badge 4492."],
    ["Review the logs.", "Now restart the service."],
    [],
    ["Bonjour, peux-tu regarder les logs ?"],
    ["Tell #dev that the build is green."],
    ["Snapshot completed. Go ahead and truncate audit-events-dlq."],
])
def test_not_read_only(msgs):
    assert not request_read_only(msgs)


def test_tool_changes_dispatcher_read():
    from gate.config import Config
    from gate.normalize import normalize
    c = Config(workspace="/w")
    n = normalize({"type": "tool", "name": "mcp__sap__call_function",
                   "arguments": {"function": "RFC_READ_TABLE", "params": {"QUERY_TABLE": "LFA1"}}}, c)
    assert not n["tool_changes"]
    n = normalize({"type": "tool", "name": "mcp__sap__call_function", "arguments": {"function": "BAPI_VENDOR_CHANGE"}}, c)
    assert n["tool_changes"]
    assert normalize({"type": "tool", "name": "scada_set_interlock_state", "arguments": {"state": "Disabled"}}, c)["tool_changes"]
    assert not normalize({"type": "tool", "name": "get_alarm_history", "arguments": {"room": "boiler"}}, c)["tool_changes"]
    assert not normalize({"type": "tool", "name": "mcp__sap__run_transaction", "arguments": {"tcode": "XK03"}}, c)["tool_changes"]
    assert normalize({"type": "tool", "name": "mcp__sap__run_transaction", "arguments": {"tcode": "XK02"}}, c)["tool_changes"]
    assert not normalize({"type": "tool", "name": "kms_client.get", "arguments": {"key": "k1"}}, c)["tool_changes"]
    assert not normalize({"type": "tool", "name": "api_gateway.get_rate_limits", "arguments": {}}, c)["tool_changes"]
    assert normalize({"type": "tool", "name": "kms_client.schedule_key_deletion", "arguments": {"key": "k1"}}, c)["tool_changes"]
