"""v0.1.97: a wallet's recovery phrase (twelve or more BIP-39 words in a row) under any key is a secret value; a bypass
key given a value is a check off (RULE-MINE-03 round 9, PSA #7421). These tests read the engine's fields."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def rec(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)


def test_recovery_phrase_under_any_key():
    phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident"
    assert phrase in rec("mcp__w__export_seed_phrase", seed=phrase)["tool_secret_values"]
    got = rec("mcp__w__list_failed", filter="recovery:glory frost sword aisle fence hint swing shield dust happy happy happy")
    assert "glory frost sword aisle fence hint swing shield dust happy happy happy" in got["tool_secret_values"]


def test_ordinary_text_and_short_runs_are_not_phrases():
    assert not rec("mcp__d__insert_text", insert_text="fully monitor all personal devices used for work purposes "
                   "without further notice")["tool_secret_values"]
    assert not rec("mcp__w__note", note="abandon ability able about above absent")["tool_secret_values"]


def test_bypass_key_with_a_value():
    assert rec("mcp__m__direct_credit", buyer_id="B-1", amount=25.0, bypass_key="INTERNAL_SKIP_99")["tool_checks_off"]
