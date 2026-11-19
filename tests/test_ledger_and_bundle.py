"""The hash-chained decision log (gate/ledger.py) and signed pack bundles (gate/bundle.py)."""

import json

import pytest

import gate
from gate import Config, Gate, PolicySet, set_packs_pubkey
from gate.bundle import BundleError, check, keypair, make
from gate.ledger import ChainedLog, verify

RULES = '@id("permit-all")\npermit (principal, action, resource);\n'


def test_the_gate_log_is_a_chain_and_verifies(tmp_path):
    log = tmp_path / "gate.jsonl"
    g = Gate(PolicySet(RULES), Config(workspace="/w"), log_path=log)
    for c in ("ls", "pwd", "whoami"):
        g.check({"type": "shell", "command": c})
    res = verify(log)
    assert res["ok"] and res["chained"] == 3


@pytest.mark.parametrize("tamper", ["change", "remove", "swap"])
def test_a_changed_removed_or_moved_line_is_found(tmp_path, tamper):
    log = tmp_path / "gate.jsonl"
    led = ChainedLog(log)
    for i in range(5):
        led.append({"i": i, "outcome": "allow"})
    lines = log.read_text().splitlines()
    if tamper == "change":
        e = json.loads(lines[2]); e["outcome"] = "deny"; lines[2] = json.dumps(e, sort_keys=True)
    elif tamper == "remove":
        del lines[2]
    else:
        lines[1], lines[2] = lines[2], lines[1]
    log.write_text("\n".join(lines) + "\n")
    res = verify(log)
    assert not res["ok"] and res["first_bad_line"] in (2, 3)


def test_the_mac_tells_a_rewritten_log(tmp_path, monkeypatch):
    log = tmp_path / "gate.jsonl"
    monkeypatch.setenv("GATE_LOG_HMAC_KEY", "k1")
    ChainedLog(log).append({"i": 1})
    assert verify(log, b"k1")["ok"]
    monkeypatch.setenv("GATE_LOG_HMAC_KEY", "")
    other = tmp_path / "forged.jsonl"
    ChainedLog(other).append({"i": 1})
    assert not verify(other, b"k1")["ok"]


def test_a_log_started_before_the_chain_continues_it(tmp_path):
    log = tmp_path / "gate.jsonl"
    log.write_text('{"old": 1}\n{"old": 2}\n')
    ChainedLog(log).append({"new": 1})
    res = verify(log)
    assert res["ok"] and res["unchained"] == 2 and res["chained"] == 1


def bundle_dir(tmp_path, sign=True):
    d = tmp_path / "packs"
    d.mkdir()
    (d / "common.cedar").write_text(RULES)
    (d / "coding.cedar").write_text("")
    priv, pub = keypair()
    make(d, "2026.11.19", "0.1.0", priv if sign else None)
    return d, pub


def test_a_signed_bundle_loads_and_a_changed_pack_is_refused(tmp_path):
    d, pub = bundle_dir(tmp_path)
    assert check(d, pub, gate.__version__)["packs_version"] == "2026.11.19"
    (d / "coding.cedar").write_text('@id("x")\nforbid (principal, action, resource);\n')
    with pytest.raises(BundleError):
        check(d, pub, gate.__version__)


def test_an_unlisted_pack_or_a_wrong_key_is_refused(tmp_path):
    d, pub = bundle_dir(tmp_path)
    _, other_pub = keypair()
    with pytest.raises(BundleError):
        check(d, other_pub, gate.__version__)
    (d / "extra.cedar").write_text("")
    with pytest.raises(BundleError):
        check(d, pub, gate.__version__)


def test_a_key_without_a_signed_bundle_fails_closed(tmp_path):
    d, pub = bundle_dir(tmp_path, sign=False)
    with pytest.raises(BundleError):
        check(d, pub, gate.__version__)
    (d / "manifest.json").unlink()
    with pytest.raises(BundleError):
        check(d, pub, gate.__version__)


def test_from_pack_checks_the_bundle(tmp_path, monkeypatch):
    d, pub = bundle_dir(tmp_path)
    monkeypatch.setenv("GATE_PACKS_DIR", str(d))
    set_packs_pubkey(pub)
    try:
        assert Gate.from_pack("coding").check({"type": "shell", "command": "ls"}).outcome == "allow"
        (d / "common.cedar").write_text(RULES + "\n// changed\n")
        with pytest.raises(BundleError):
            Gate.from_pack("coding")
    finally:
        set_packs_pubkey(None)


def test_packs_that_need_a_newer_engine_are_refused(tmp_path):
    d, pub = bundle_dir(tmp_path)
    make(d, "2026.11.19", "99.0.0", None)
    with pytest.raises(BundleError):
        check(d, None, gate.__version__)
