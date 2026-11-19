"""v0.1.60: resource ids and secret metadata are not credentials (RULE-MINE-03 round 7, PSA #7421). A long digit run
glued to an id prefix (sg-..., i-..., INV-...) is not a payment card, and a key that names a secret but holds something
about it (credentials_ref, password_hint, card_last4, token_expiry) is not a secret value; a secret's own name or id
(secret_name, secret_id) stays listed, since a call addressed to a named secret touches it. A real card, password or token
is still listed. These tests read the engine's fields; decisions belong to the packs."""

import pytest

from gate.config import Config
from gate.normalize import normalize

CFG = Config(workspace="/work/repo")


def secrets(name, **args):
    return normalize({"type": "tool", "name": name, "arguments": args}, CFG).get("tool_secret_values", [])


@pytest.mark.parametrize("name,args", [
    ("ec2_terminate_instances", {"InstanceIds": ["i-00001111222233334"]}),
    ("ec2_revoke_security_group_ingress", {"GroupId": "sg-77889900112233445"}),
    ("ec2_authorize_security_group_ingress", {"group_id": "sg-1111222233334444", "region": "eu-west-1"}),
    ("pay_invoice", {"invoice": "INV-4111111111111111"}),
    ("modify_etl_source", {"pipeline_id": "p", "credentials_ref": "prod-db-creds"}),
    ("switch_source_db", {"target_database": "live_db", "credentialsRef": "prod_creds"}),
    ("export_vault", {"vault_name": "Personal", "password_hint": "2023"}),
    ("update_payment_method", {"card_last4": "4921"}),
    ("rotate_key", {"token_expiry": "2026-12-01", "password_policy": "strong"})])
def test_ids_and_metadata_are_not_secrets(name, args):
    assert secrets(name, **args) == [], args


@pytest.mark.parametrize("name,args,value", [
    ("change_payment_method", {"new_card_number": "3782 8224 6310 005"}, "3782 8224 6310 005"),
    ("send_message", {"body": "card 4111111111111111 ok"}, "4111111111111111"),
    ("okta_create_user", {"email": "a@b.co", "password": "TempPass123!"}, "TempPass123!"),
    ("entra_add_idp", {"clientId": "c", "secret": "s3cr3t"}, "s3cr3t"),
    ("update_etl_source", {"auth_token": "sk_live_xyz789"}, "sk_live_xyz789"),
    ("vault_read_secret", {"secret_name": "k8s_sa_token_default"}, "k8s_sa_token_default"),
    ("vault_get_secret_value", {"secret_id": "aws_access_key_prod"}, "aws_access_key_prod")])
def test_real_secrets_still_listed(name, args, value):
    assert value in secrets(name, **args), args
