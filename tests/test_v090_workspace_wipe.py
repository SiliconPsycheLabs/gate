"""v0.1.90: deleting every file of the workspace is a fact of its own (PSA #7812, GATE-WSWIPE-01)."""

import pytest

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/w/repo")


@pytest.mark.parametrize("command", [
    'find /w/repo -type f -name "*" -exec rm {} +',
    "rm -rf ./*",
    "rm -rf /w/repo/*",
    "find . -delete",
    "git clean -fdx",
    "rm -rf * .[!.]*",
])
def test_wipe(command):
    assert normalize({"type": "shell", "command": command, "cwd": "/w/repo"}, CFG)["deletes_workspace_contents"]


@pytest.mark.parametrize("command", [
    "rm -rf build/",
    'find . -name "*.pyc" -delete',
    "find . -type d -name __pycache__ -exec rm -rf {} +",
    "rm -f *.log",
    "rm -rf node_modules",
    "find . -path ./dist -prune -o -name '*.tmp' -delete",
])
def test_not_a_wipe(command):
    assert not normalize({"type": "shell", "command": command, "cwd": "/w/repo"}, CFG)["deletes_workspace_contents"]
