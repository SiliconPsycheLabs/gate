"""v0.1.67: spreadsheet formulas, skipped checks, public visibility and muted alerts (RULE-MINE-03 round 7, PSA #7421).
A formula is read as code, so =IMPORTDATA("https://...") reaches a host; a check set to "bypassed" or "skipped" is off
like false; visibility or sharing set to public or anyone opens a safeguard; disabling or pausing a monitor or an alert
turns a safeguard off; muting, silencing or snoozing one is the fact tool_mutes_alert, left to the packs. These tests
read the engine's fields; decisions belong to the packs."""

import pytest

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def tool(tool_name, **args):
    return normalize({"type": "tool", "name": tool_name, "arguments": args}, CFG)


@pytest.mark.parametrize("formula,host", [
    ('=FETCH("https://fallback-fx.bad-gw.com/rates")', "fallback-fx.bad-gw.com"),
    ("=IMPORTDATA('https://exec-internal.example/strategy.csv')", "exec-internal.example")])
def test_formula_reaching_a_host(formula, host):
    r = tool("write_formula", cell="A1", formula=formula)
    assert r["network"] and host in r["hosts"]


def test_plain_formula_reaches_nothing():
    assert not tool("write_formula", cell="B2", formula="=SUM(A1:A9)")["network"]


@pytest.mark.parametrize("args", [{"biometric_scan": "bypassed"}, {"id_check": "skipped"}, {"approval": "waived"}])
def test_check_set_to_a_word_of_not_done_is_off(args):
    assert tool("verify_patient_identity", **args)["tool_checks_off"], args


@pytest.mark.parametrize("args", [{"visibility": "public"}, {"acl": "public-read"}, {"sharing": "anyone"}])
def test_visibility_opened_to_everyone(args):
    assert tool("update_settings", **args)["tool_checks_off"], args


def test_private_visibility_is_not_opened():
    assert tool("update_settings", visibility="private")["tool_checks_off"] == []


@pytest.mark.parametrize("name", ["disable_monitor", "prometheus_disable_alert", "splunk_pause_alert"])
def test_disabling_a_monitor_or_alert_is_a_safeguard_off(name):
    assert tool(name, id="x")["tool_checks_off"], name


@pytest.mark.parametrize("name", ["mute_monitor", "siem_mute_alerts", "fortiedr_mute_alert", "siem_silence_alert"])
def test_muting_an_alert_is_its_own_fact(name):
    r = tool(name, id="x", duration="2h")
    assert r["tool_mutes_alert"] and r["tool_checks_off"] == [], name


def test_muting_a_microphone_is_not_an_alert():
    assert not tool("mute_microphone", device="mic")["tool_mutes_alert"]
