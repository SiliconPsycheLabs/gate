"""v0.1.80: a network range open to the world inside a list, and an endpoint opened to the internet (GATE-SCOUT-01,
PSA #7421). These tests read the engine's fields; decisions belong to the packs."""

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/workspace")


def off(tool_name, **args):
    return normalize({"type": "tool", "name": f"mcp__cloud__{tool_name}", "arguments": args}, CFG)["tool_checks_off"]


def test_world_cidr_inside_a_list():
    assert off("security_group_create", name="sg", ingress_rules=[{"protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}])


def test_private_cidr_list_is_not_open():
    assert not off("security_group_create", name="sg", ingress_rules=[{"cidr_blocks": ["10.0.0.0/8"]}])


def test_public_endpoint_switched_on():
    assert off("terraform_apply", target="module.eks", var={"cluster_endpoint_public_access": True})
    assert off("create_db_instance", name="db", publicly_accessible=True)


def test_public_endpoint_switched_off_is_not_open():
    assert not off("create_db_instance", name="db", publicly_accessible=False)
