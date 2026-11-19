"""A task contract: what one session's work may touch, declared when the session opens (PSA prior-art review, after
Progent, Watchlight's pre-flight manifest and CaMeL's plan fixed from the trusted request).

The owner, or the orchestrator that starts the agent, writes the contract from the task before the agent reads any
data. The gate compares each action with it and lists what falls outside, deterministically; the rules decide what to
do with that list (the maintained packs hold the action for a person). A person's approval widens the contract for
that value, for the rest of the session. No contract, or a dimension left out of it, constrains nothing.

    {"tools": ["mcp__crm__*", "Read"],            # tool names, shell-style patterns
     "hosts": ["api.example.com", "*.corp.example"],   # hosts the work may reach; "*." matches subdomains
     "targets": ["anna@example.com", "acct_42"],   # recipients, accounts, ids a tool may send to or act on
     "paths": ["/srv/app", "/data/exports/*"]}     # directories or patterns the work may write or delete under
"""

from __future__ import annotations

import fnmatch

DIMENSIONS = ("tools", "hosts", "targets", "paths")


def clean(contract) -> dict | None:
    """The contract as the engine reads it: known dimensions only, lists of non-empty strings. Raises ValueError on
    anything else, so a typo cannot leave a dimension unconstrained."""
    if contract in (None, {}):
        return None
    if not isinstance(contract, dict):
        raise ValueError("contract must be an object")
    out = {}
    for k, v in contract.items():
        if k not in DIMENSIONS:
            raise ValueError(f"unknown contract dimension {k!r}; allowed: {', '.join(DIMENSIONS)}")
        if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
            raise ValueError(f"contract.{k} must be a list of non-empty strings")
        out[k] = [x.strip() for x in v]
    return out


def _host_in(host: str, patterns: list[str]) -> bool:
    h = host.lower().rstrip(".")
    for p in patterns:
        p = p.lower().rstrip(".")
        if p.startswith("*."):
            if h.endswith(p[1:]) or h == p[2:]:
                return True
        elif h == p:
            return True
    return False


def _path_in(path: str, patterns: list[str]) -> bool:
    for p in patterns:
        p = p.rstrip("/") or "/"
        if any(c in p for c in "*?["):
            if fnmatch.fnmatchcase(path, p):
                return True
        elif path == p or path.startswith(p + "/") or p == "/":
            return True
    return False


def outside(record: dict, contract: dict | None, widened: set) -> list[str]:
    """What this action touches outside the contract, as "tool:<name>", "host:<h>", "target:<v>", "path:<p>",
    sorted; values a person already approved in this session are left out."""
    if not contract:
        return []
    out: set[str] = set()
    tools = contract.get("tools")
    name = record.get("tool_name") or ""
    if tools is not None and name and not any(fnmatch.fnmatchcase(name, p) for p in tools):
        out.add(f"tool:{name}")
    hosts = contract.get("hosts")
    if hosts is not None:
        out.update(f"host:{h}" for h in record.get("hosts", []) if not _host_in(h, hosts))
    targets = contract.get("targets")
    if targets is not None:
        allowed = {t.strip().lower() for t in targets}
        values = set(record.get("tool_targets", [])) | set(record.get("tool_send_targets", [])) | \
            set(record.get("payment_targets", []))
        out.update(f"target:{v}" for v in values if str(v).strip().lower() not in allowed)
    paths = contract.get("paths")
    if paths is not None:
        out.update(f"path:{p}" for p in set(record.get("writes", [])) | set(record.get("deletes", []))
                   if not _path_in(p, paths))
    return sorted(x for x in out if x not in widened)
