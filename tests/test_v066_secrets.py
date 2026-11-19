"""v0.1.66: credentials in tool names, SQL, Redis and one-time codes; privileged containers (RULE-MINE-03 round 7,
PSA #7421). A tool that hands out a credential named in its own name reads a secret the way a secret-store read does;
password='...' in SQL and CONFIG SET requirepass in Redis carry a credential; one-time, backup and recovery codes and
PINs are secret values, while a field about how a code is delivered is not; a container given the host's powers opens
a safeguard; a browser's cookie store, an API key file and the MySQL user table are credential files. These tests read
the engine's fields; decisions belong to the packs."""

import pytest

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def tool(tool_name, **args):
    return normalize({"type": "tool", "name": tool_name, "arguments": args}, CFG)


@pytest.mark.parametrize("name,args", [
    ("export_private_key", {"key_path": "/home/user/backdoor.key"}),
    ("get_api_key", {"service": "billing"}),
    ("dump_passwords", {"vault": "team"}),
    ("export_passwords", {"vault_name": "Personal", "format": "csv"})])
def test_tools_that_hand_out_a_credential_read_a_secret(name, args):
    assert tool(name, **args)["tool_reads_secret"], name


@pytest.mark.parametrize("name,args", [
    ("list_secrets", {}), ("get_password_policy", {}), ("check_password_strength", {"length": 12}),
    ("get_key_rotation_status", {"key_id": "k1"})])
def test_names_and_policies_are_not_secret_reads(name, args):
    assert not tool(name, **args)["tool_reads_secret"], name


@pytest.mark.parametrize("name,args,value", [
    ("sql_execute", {"query": "UPDATE auth SET password='Admin123!' WHERE user='admin'"}, "Admin123!"),
    ("redis_execute", {"command": "CONFIG SET requirepass admin123"}, "admin123"),
    ("search_slots", {"duration": 120, "mfa_code": "99-221-558"}, "99-221-558"),
    ("update_master_settings", {"recovery_code": "RC-7723-ALPHA-X9"}, "RC-7723-ALPHA-X9"),
    ("unlock_vehicle", {"pin": "8842"}, "8842")])
def test_credentials_in_text_and_codes_are_listed(name, args, value):
    assert value in tool(name, **args)["tool_secret_values"], args


def test_how_a_code_is_delivered_is_not_a_secret():
    assert tool("add_emergency_contact", name="Mike", recovery_code_delivery="sms")["tool_secret_values"] == []
    assert tool("send_message", text="password reset done")["tool_secret_values"] == []


@pytest.mark.parametrize("args", [{"image": "x", "privileged": True}, {"name": "web", "hostPID": True},
                                  {"image": "x", "host_network": True}])
def test_host_powers_on_a_container_open_a_safeguard(args):
    assert tool("docker_run", **args)["tool_checks_off"], args


@pytest.mark.parametrize("path", ["~/.config/google-chrome/Default/Cookies", "~/.config/google-chrome/Cookies",
                                  "/srv/app/config/api_keys.json"])
def test_credential_files_are_secret_reads(path):
    assert tool("read_file", path=path)["reads_secret"], path
