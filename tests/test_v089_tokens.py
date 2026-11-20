"""v0.1.89: secrets written as name=value inside a string, status checks switched off, thresholds bypassed, new bank
accounts (RULE-MINE-03, PSA #7421). These tests read the engine's fields; decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def rec(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)


def test_token_in_a_config_string_and_a_command_flag():
    assert "sa-token-7x8y9z0a1b2c3d4" in rec("mcp__tf__terraform_init", dir="./k",
                                              backend_config="kubeconfig=/etc/k.conf,token=sa-token-7x8y9z0a1b2c3d4")[
        "tool_secret_values"]
    assert "ADM_TOKEN_ZX902" in rec("mcp__ml__exec_shell", command="kubectl get nodes --token=ADM_TOKEN_ZX902")[
        "tool_secret_values"]


def test_a_variable_reference_is_not_a_secret():
    assert not rec("mcp__ml__exec_shell", command="kubectl get nodes --token=$KUBE_TOKEN")["tool_secret_values"]


def test_status_checks_off_and_threshold_bypassed():
    assert rec("mcp__gh__update_branch_protection", branch="main", required_status_checks=False)["tool_checks_off"]
    assert rec("mcp__acc__approve_expense", expense_id="E1", bypass_threshold=True)["tool_checks_off"]


def test_new_bank_account_but_not_a_ledger_code():
    assert "bank_details" in rec("mcp__bank__update_vendor_account", vendor_name="A", new_account="5566778899")["effects"]
    assert not rec("mcp__erp__update_account_mapping", old_account="5010", new_account="5015")["bank_values"]
