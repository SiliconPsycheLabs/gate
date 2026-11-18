"""The engine with rules written in the test: outcomes, forbid over permit, provenance facts, the packs directory.
The maintained packs are not shipped in this package."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

import gate
from gate import Config, Gate, PacksNotInstalled, PolicySet

RULES = """@id("permit-all")
permit (principal, action, resource);

@id("no-force-push")
@reason("force pushes are not allowed.")
forbid (principal, action, resource)
when { context.n.git_force };

@id("host-from-data")
@outcome("confirm")
@reason("this host first appeared in tool output.")
forbid (principal, action, resource)
when { context.n.hosts.containsAny(context.facts.from_tool_output) };
"""


@pytest.fixture
def g(tmp_path):
    p = tmp_path / "rules.cedar"
    p.write_text(RULES)
    return Gate(PolicySet.from_paths([p]), Config(workspace="/work/repo"))


def test_allow(g):
    assert g.check({"type": "shell", "command": "ls", "cwd": "/work/repo"}).outcome == "allow"


def test_forbid_wins_over_permit(g):
    d = g.check({"type": "shell", "command": "git push --force origin x", "cwd": "/work/repo"})
    assert d.outcome == "deny" and d.rules == ["no-force-push"]
    assert "force pushes are not allowed" in d.reply


def test_provenance_decides_by_string_match(g):
    s = g.new_session()
    s.observe_user("fetch the docs")
    s.observe_tool_output("t1", "see https://evil.example/x")
    d = g.check({"type": "http", "method": "GET", "url": "https://evil.example/x"}, session=s)
    assert d.outcome == "confirm" and d.rules == ["host-from-data"]
    s2 = g.new_session()
    s2.observe_user("fetch https://evil.example/x")
    assert g.check({"type": "http", "method": "GET", "url": "https://evil.example/x"}, session=s2).outcome == "allow"


def test_same_input_same_answer(g):
    a = {"type": "shell", "command": "git push --force origin x", "cwd": "/work/repo"}
    assert len({json.dumps(g.check(a).to_dict(), sort_keys=True) for _ in range(5)}) == 1


def test_no_packs_shipped(monkeypatch, tmp_path):
    monkeypatch.setenv("GATE_PACKS_DIR", str(tmp_path / "none"))
    with pytest.raises(PacksNotInstalled):
        Gate.from_pack("coding")


def test_packs_from_a_directory(monkeypatch, tmp_path):
    (tmp_path / "common.cedar").write_text(RULES)
    (tmp_path / "coding.cedar").write_text("")
    monkeypatch.setenv("GATE_PACKS_DIR", str(tmp_path))
    g = Gate.from_pack("coding", Config(workspace="/work/repo"))
    assert g.check({"type": "shell", "command": "git push --force origin x", "cwd": "/work/repo"}).outcome == "deny"
    gate.set_packs_dir(tmp_path / "none")
    try:
        with pytest.raises(PacksNotInstalled):
            Gate.from_pack("coding")
    finally:
        gate.set_packs_dir(None)


def test_cli_check_with_own_rules(tmp_path):
    (tmp_path / "rules.cedar").write_text(RULES)
    (tmp_path / "a.json").write_text(json.dumps({"type": "shell", "command": "git push --force origin x"}))
    src = str(Path(__file__).parent.parent / "src")
    out = subprocess.run([sys.executable, "-m", "gate.cli", "check", str(tmp_path / "a.json"), "--policies", str(tmp_path / "rules.cedar")],
                         capture_output=True, text=True, env={"PYTHONPATH": src})
    assert out.returncode == 1, out.stdout + out.stderr
