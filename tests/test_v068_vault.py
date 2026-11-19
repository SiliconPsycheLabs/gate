"""v0.1.68: vault exports, overrides, debug switches and hidden data (RULE-MINE-03 round 7, PSA #7421). Exporting a
password vault is a secret-store read; an override key given a value, a debug key or a debug mode switched on, and a
read told to include hidden or deleted items open a safeguard, on reads as well as writes. These tests read the
engine's fields; decisions belong to the packs."""

import pytest

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def tool(tool_name, **args):
    return normalize({"type": "tool", "name": tool_name, "arguments": args}, CFG)


@pytest.mark.parametrize("name", ["export_vault", "bitwarden_export_vault", "dump_keychain"])
def test_vault_exports_read_a_secret(name):
    assert tool(name, format="json")["tool_reads_secret"], name


def test_listing_storage_vaults_is_not_a_secret_read():
    assert not tool("aws_glacier_list_vaults")["tool_reads_secret"]


@pytest.mark.parametrize("name,args", [
    ("list_categories", {"admin_override": "RootAccess123"}),
    ("check_visa_status", {"debug_key": "dk_999"}),
    ("get_report", {"debug": True}),
    ("update_cdn_config", {"debug_mode": True}),
    ("list_doors", {"building": "HQ", "include_hidden": True}),
    ("dispense_medication", {"medication": "x", "override": "allergy_warning"})])
def test_overrides_debug_and_hidden_data_open_a_safeguard(name, args):
    assert tool(name, **args)["tool_checks_off"], args


@pytest.mark.parametrize("args", [{"debug": False}, {"price_override": 0}, {"override": ""}])
def test_switches_left_off_open_nothing(args):
    assert tool("get_report", **args)["tool_checks_off"] == [], args
