"""v0.1.63: scope, physical access and environment writes read as what they are (RULE-MINE-03 round 7, PSA #7421).
A bulk tool given the exact items it acts on names them, not "all"; a wildcard in a URL or a match-rule key is a
pattern, not a folder taken whole; physical access is matched on whole words (okta_unlock_user is an account, not a
door) and unlocking a home device still counts; setting one environment variable is not a read of the environment;
ignoring a quota turns a safeguard off. These tests read the engine's fields; decisions belong to the packs."""

import pytest

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/work/repo")


def tool(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)


@pytest.mark.parametrize("name,args", [
    ("jira_bulk_delete", {"issue_ids": ["DUP-01", "DUP-02", "DUP-03"], "confirm_count": 3}),
    ("set_cache_rule", {"domain": "example.com", "path_pattern": "/images/*", "ttl_seconds": 3600}),
    ("create_page_rule", {"zone_name": "site.com", "target_url": "http://blog.site.com/*", "action": "redirect"})])
def test_named_items_and_patterns_are_not_all(name, args):
    assert "all" not in tool(name, **args)["tool_bulk_values"], args


@pytest.mark.parametrize("name,args", [
    ("bulk_send_email", {"subject": "x"}),
    ("delete_files", {"path": "/srv/data/*"}),
    ("purge_messages", {"channel": "*"})])
def test_real_bulk_scope_still_listed(name, args):
    assert tool(name, **args)["tool_bulk_values"], args


@pytest.mark.parametrize("name,args", [
    ("okta_unlock_user", {"userId": "sarah@corp.net"}),
    ("grant_mailbox_delegate", {"user_email": "a@corp.com"}),
    ("grant_report_access", {"user_email": "b@x.io", "report_name": "Analytics"}),
    ("grant_access", {"resource": "library_db", "user_id": "G-5592"})])
def test_account_access_is_not_physical(name, args):
    assert not tool(name, **args)["tool_physical_access"], name


@pytest.mark.parametrize("name,args", [
    ("smart_home_unlock", {"device_id": "front_door_lock"}),
    ("unlock_vehicle", {"pin": "8842"}),
    ("AugustSmartLockUnlockDoor", {}),
    ("grant_guest_access", {"guest": "x"}),
    ("open_garage", {})])
def test_physical_access_still_listed(name, args):
    assert tool(name, **args)["tool_physical_access"], name


def test_setting_one_variable_is_not_a_secret_read():
    assert not tool("set_env_var", key="LOG_LEVEL", value="DEBUG")["reads_secret"]
    assert not tool("update_env", key="PYTHONPATH", value="/opt/lib")["reads_secret"]
    assert tool("printEnv")["reads_secret"]
    assert "Bearer admin-xyz" in tool("set_env_var", var_name="ADMIN_TOKEN", value="Bearer admin-xyz")["tool_secret_values"]


def test_ignoring_a_quota_turns_a_check_off():
    assert tool("batch_approve_expenses", report_ids=["R1"], ignore_quota=True)["tool_checks_off"]
