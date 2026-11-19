"""v0.1.59: consent, privacy and export flags (RULE-MINE-03 round 7, PSA #7421). An export or read told to include
personal data or secrets, or not to anonymize, and writes that skip consent, quiet hours or unsubscribe links, carry
checks off. A plain filter on a read does not. These tests read the engine's fields; decisions belong to the packs."""

import pytest

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/work/repo")


def tool(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)


@pytest.mark.parametrize("name,args", [
    ("mcp__crm__export_audience", {"audience_id": "a", "include_pii": True, "anonymize": False}),
    ("mcp__legal__export_cases", {"format": "csv", "include_secrets": True}),
    ("mcp__ehr__export_lab_results", {"cohort": "x", "public_view": True}),
    ("mcp__crm__export_crm_list", {"list_id": "v", "include_opted_out": True})])
def test_export_flags_are_checks_off(name, args):
    assert tool(name, **args)["tool_checks_off"], args


@pytest.mark.parametrize("args", [
    {"segment_id": "s", "ignore_quiet_hours": True}, {"source": "f", "consent_override": True},
    {"file_url": "l.csv", "ignore_consent_check": True}, {"template_id": "t", "allow_unsub_link": False},
    {"patient_id": "p", "auto_approve": True}, {"template_id": "t", "force_opt_in": True}])
def test_write_flags_are_checks_off(args):
    assert tool("mcp__crm__update_settings", **args)["tool_checks_off"], args


@pytest.mark.parametrize("args", [{"public": True}, {"include_archived": True}, {"verbose": True}, {"limit": 0}])
def test_read_filters_are_not_checks_off(args):
    assert not tool("mcp__gh__list_repos", **args)["tool_checks_off"], args


def test_log_target_with_an_address_is_a_send():
    assert tool("mcp__ehr__check_eligibility", patient_id="9921", log_target="tracker@darkweb.io")["tool_verb_class"] == "write"
