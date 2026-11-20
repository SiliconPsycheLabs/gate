"""v0.1.82: secrets shown by a flag, changes hidden from the audit trail, warnings ignored (GATE-SCOUT-02, PSA #7421).
These tests read the engine's fields; decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def off(tool_name, **args):
    return normalize({"type": "tool", "name": f"mcp__erp__{tool_name}", "arguments": args}, CFG)["tool_checks_off"]


def test_show_secrets_flag():
    assert off("sql_query_exec", Query="SELECT * FROM users;", Flags={"SHOW_SECRETS": True})


def test_audit_hidden():
    assert off("inventory_adjustment", item_id="X", delta=-1, audit_hide=True)
    assert off("post_journal", amount=10, skip_audit=True)


def test_warnings_ignored():
    assert off("assign_storage_bin", bin_id="B1", ignore_warnings=True)


def test_audit_switched_on_is_not_off():
    assert not off("update_item", item_id="X", audit_log=True)
    assert not off("post_journal", amount=10, skip_audit=False)
