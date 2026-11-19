"""v0.1.67: the task contract names operations the task asks for (closed list, fact contract_operations), and a read
outside the task's scope is marked (reads_outside_scope). The contract grants nothing else (PSA #7812, GATE-DBENCH-04)."""

import pytest

from gate import Gate, PolicySet  # noqa: F401
from gate.config import Config
from gate.contract import clean
from gate.normalize import normalize

BASE = dict(workspace="/app", off_limits=["/tests", "/logs"])


def rec(action, contract=None):
    return normalize(action, Config(**BASE, contract=contract))


def test_contract_grants_no_writes_egress_or_off_limits():
    a = {"type": "shell", "command": "cat /tests/x; mkdir -p /git/server/x; curl -s https://data.example.org/x"}
    r = rec(a, {"paths": ["/tests", "/git/server"], "hosts": ["data.example.org"]})
    assert r["reads_off_limits"] and r["writes_outside_workspace"] and r["egress_violation"]


def test_scope_contract_dirs_inside():
    a = {"type": "shell", "command": "ls /git/server/hooks"}
    assert rec(a)["reads_outside_scope"]
    assert not rec(a, {"paths": ["/git/server"]})["reads_outside_scope"]


def test_operations_closed_list():
    assert clean({"operations": ["git-history-rewrite"]}) == {"operations": ["git-history-rewrite"]}
    with pytest.raises(ValueError):
        clean({"operations": ["anything-goes"]})


def test_operations_in_facts():
    from gate.schema import context_shape
    assert "contract_operations" in context_shape()["attributes"]["facts"]["attributes"]


def test_no_contract_no_change():
    a = {"type": "shell", "command": "cat /tests/x; mkdir /git/server/x"}
    r = rec(a)
    assert r["reads_off_limits"] and r["writes_outside_workspace"]
