"""Cedar schema for the gate's request context, generated from the record defaults.

Used by `gate validate`: a rule that names a field that does not exist is reported before it runs.
"""

from __future__ import annotations

import json

from .checker import KNOWN_ACTIONS
from .normalize import default_record


def _type_of(v):
    if isinstance(v, bool):
        return {"type": "Boolean"}
    if isinstance(v, int):
        return {"type": "Long"}
    if isinstance(v, str):
        return {"type": "String"}
    if isinstance(v, list):
        return {"type": "Set", "element": {"type": "String"}}
    raise TypeError(v)


def context_shape() -> dict:
    n = {k: _type_of(v) for k, v in default_record().items()}
    strset = {"type": "Set", "element": {"type": "String"}}
    facts = {
        "from_user": strset, "from_system": strset, "from_tool_output": strset, "from_model": strset,
        "secret_read_in_session": {"type": "Boolean"},
        "tool_definition_changed": {"type": "Boolean"},
        "git_remote_not_from_user": {"type": "Boolean"},
        "bank_changed_in_session": {"type": "Boolean"},
        "asset_writes_in_session": {"type": "Long"},
        "reads_fetched": {"type": "Boolean"},
        "reads_outside_scope_unnamed": {"type": "Boolean"},
        "writes_outside_workspace_unnamed": {"type": "Boolean"},
        "deletes_outside_workspace_unnamed": {"type": "Boolean"},
        "reads_fetched_eval": {"type": "Boolean"},
        "reads_unowned_shared": {"type": "Boolean"},
        "denials_in_session": {"type": "Long"},
        "holds_in_session": {"type": "Long"},
        "outside_contract": strset,
        "contract_operations": strset,
    }
    config = {
        "workspace": {"type": "String"}, "egress_hosts": strset, "egress_listed": {"type": "Boolean"}, "environment": {"type": "String"},
        "change_window": {"type": "Boolean"}, "default_branches": strset,
        "assets_registered": {"type": "Boolean"}, "money_limit": {"type": "Long"}, "contract_declared": {"type": "Boolean"},
        "off_limits_declared": {"type": "Boolean"},
    }
    return {"type": "Record", "attributes": {
        "n": {"type": "Record", "attributes": n},
        "facts": {"type": "Record", "attributes": facts},
        "config": {"type": "Record", "attributes": config},
    }}


def schema_json() -> str:
    ctx = context_shape()
    actions = {a: {"appliesTo": {"principalTypes": ["Agent"], "resourceTypes": ["Target"], "context": ctx}}
               for a in KNOWN_ACTIONS}
    return json.dumps({"": {
        "entityTypes": {
            "Agent": {},
            "Target": {},
        },
        "actions": actions,
    }})
