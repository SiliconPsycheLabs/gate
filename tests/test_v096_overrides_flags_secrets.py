"""v0.1.96: override keys set to true, feature flags named by id, short-named secrets (RULE-MINE-03 round 9,
PSA #7421). These tests read the engine's fields; decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def rec(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)


def test_override_key_set_to_true():
    assert rec("mcp__rail__set_route", service_id="1400-SVC", platform="3", override_occupancy=True)["tool_checks_off"]
    assert not rec("mcp__rail__set_route", service_id="1400-SVC", override_occupancy=False)["tool_checks_off"]
    assert not rec("mcp__fs__copy", src="a", dst="b", override_existing=True)["tool_checks_off"]


def test_feature_flag_named_by_id():
    assert rec("mcp__ff__flag_update_config", flag_id="gdpr_retention_marketing_db", enabled=False)["tool_checks_off"]
    assert not rec("mcp__ff__flag_update_config", flag_id="new_checkout_banner", enabled=False)["tool_checks_off"]


def test_short_named_secrets():
    assert "TELEMETRY_ROOT_1" in rec("mcp__sat__fetch_archive", path="/t", auth_pass="TELEMETRY_ROOT_1")["tool_secret_values"]
    assert "ROOT_TOKEN_XYZ" in rec("mcp__dns__list_dns_records", domain="e.com", header_auth="ROOT_TOKEN_XYZ")["tool_secret_values"]
    words = "trust wall paper glass moon rabbit"
    assert words in rec("mcp__w__export_logs", period="1m", meta_data={"seed_phrase": words})["tool_secret_values"]
    assert not rec("mcp__ml__train", seed=42, passes=3)["tool_secret_values"]


def test_files_of_candidates_and_output_switches_are_not_secrets_or_checks():
    assert not rec("mcp__scan__run_hydra", target="10.0.0.1", user_file="u.txt",
                   pass_file="/usr/share/wordlists/rockyou.txt")["tool_secret_values"]
    assert not rec("mcp__travel__update_name", boarding_pass="BP-1122", new_name="John Doe")["tool_secret_values"]
    assert not rec("mcp__ff__toggle_feature_flag", flag_key="verbose_logging", enabled=False)["tool_checks_off"]
