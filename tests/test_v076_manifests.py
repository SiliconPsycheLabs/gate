"""v0.1.76: Maven and Gradle manifests, connection credentials, forced actions (GATE-SCOUT-01, PSA #7421). A dependency
written into pom.xml or build.gradle is a package install like one in requirements.txt; a connection credential
written as NAME=user:password is a secret value; a forced action (force=true, force_install, force_sync) turns its own
checks off. These tests read the engine's fields; decisions belong to the packs."""

import pytest

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def tool(tool_name, **args):
    return normalize({"type": "tool", "name": tool_name, "arguments": args}, CFG)


def test_maven_dependency_is_a_package_install():
    pom = ("<dependencies>\n <dependency>\n  <groupId>org.springframework</groupId>\n"
           "  <artifactId>evil-starter</artifactId>\n  <version>1.0</version>\n </dependency>\n</dependencies>")
    r = tool("write_file", path="pom.xml", content=pom)
    assert r["package_install"] and "org.springframework:evil-starter" in r["packages"]


def test_gradle_dependency_is_a_package_install():
    r = tool("write_file", path="build.gradle", content="dependencies {\n implementation 'com.evil:loader:2.1'\n}")
    assert r["package_install"] and "com.evil:loader" in r["packages"]


def test_connection_credential_is_a_secret():
    assert "prod:pass123" in tool("export_csv", metadata="DB_STRING=prod:pass123", rows=10)["tool_secret_values"]


def test_a_time_is_not_a_credential():
    assert tool("set_config", note="time 10:30 ratio 3:4")["tool_secret_values"] == []


@pytest.mark.parametrize("args", [{"force": True}, {"force_sync": True}, {"force_install": "true"}])
def test_forced_actions_turn_their_checks_off(args):
    assert tool("install_patch", component="driver", **args)["tool_checks_off"], args


def test_force_false_is_nothing():
    assert tool("install_patch", component="driver", force=False)["tool_checks_off"] == []
