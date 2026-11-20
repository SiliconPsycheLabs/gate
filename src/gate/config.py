"""Operator configuration: what the owner declares about the environment the agent runs in."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
import os
import json


DEFAULT_REGISTRIES = {
    "pip": ["pypi.org", "files.pythonhosted.org"],
    "npm": ["registry.npmjs.org"],
    "cargo": ["crates.io", "static.crates.io", "index.crates.io"],
    "gem": ["rubygems.org"],
    "go": ["proxy.golang.org", "sum.golang.org"],
}


DEFAULT_MODEL_PATHS = ["~/.cache/huggingface", "~/.cache/torch/hub", "~/.ollama/models", "~/.cache/lm-studio/models"]


@dataclass
class Config:
    """Everything the rules may read about the deployment, set by the owner.

    workspace: the directory the agent is allowed to change.
    egress_hosts: hosts the agent may contact without a person. A leading "*." matches subdomains.
    environment: free label, the packs know "dev", "staging" and "production".
    change_window: True while a declared change window is open (ops pack).
    default_branches: branches a push to which is treated as a push to the default branch.
    git_remotes: hosts of the git remotes (added to egress automatically).
    extra_writable: directories writable besides the workspace (default /tmp; set [] to forbid).
    home: the agent's home directory, which `~` stands for (default: the home of the user the gate runs as; set it
        when the gate runs on another machine or as another user, as a hosted gate does).
    workspaces_root: the directory that holds the workspaces of several agents or sessions on the same machine
        (default unset). When set, a read inside another workspace under it is marked in the record.
    model_paths: directories that hold the models in use (a served model, a base model, the local model caches).
        Any write, move or deletion under them sets writes_model_weights. Default: the Hugging Face, torch,
        Ollama and LM Studio caches under the agent's home; add the directory your serving engine loads.
    trusted_tools: the tools whose output is the owner's own records (patterns on the tool id the caller passes to
        observe_tool_output, e.g. "get_order_details", "crm_lookup_*"). A value read there counts as trusted, like the
        operator's configuration, and not as data from outside: an order id the agent looked up in the shop's own
        database and then uses in a change is not held as if a web page had planted it. Default none: every tool
        output is outside data. List only tools that read the owner's own systems, never a web page, an email, a
        document or a message, which is where an injection travels.
    collect_accounts: the owner's own accounts, where money owed to the owner is collected (an IBAN, an account
        number). An action that writes only these (an invoice that tells the customer where to pay) does not change
        a payee's bank details, so it is not held or refused as one and does not count as a bank change in the
        session (v0.1.91, PSA #7946). List only accounts the owner holds.
    self_ids: the identities of the agent itself or of the person it acts as (an employee number, a user id, the
        person's own account). A pay change or a payment for one of these is the agent dealing with itself, and the
        record says so (fact targets_self, v0.1.91, PSA #7946).
    declared_tools: the tools the owner gave the agent (patterns on the tool name, e.g. "sys_monitor",
        "mcp__crm__*"). When set, a call to any other tool is marked in the record: a tool that appeared in the
        agent's tool list without the owner putting it there (a poisoned MCP server, a planted plugin) does not run on
        its own. Default none: every tool may be called.
    assets: the owner's register of machines and machine-side targets (PSA #7802). Each entry is a dict:
        {"match": "<pattern or list of patterns on asset ids>", "class": "production" | "safety" | "lab" | ...,
         "min": <int>, "max": <int>, "max_writes": <int>}. Asset ids are "<domain>:<target>" as the record names them
        (modbus:10.0.4.21/40001, opcua:ns=2;s=Line1.Oven.Setpoint, home:lock.front_door, mqtt:plant/+/cmd,
        ros:/cmd_vel, gcode:haas-vf2). A write to an asset that matches no entry is marked undeclared; a value
        outside [min, max] of a matching entry is marked outside its envelope; max_writes caps how many writes to it
        one session may make without a person. Default none: every machine write is undeclared.
    money_limit: the amount (whole units of the account's currency) up to which a posting, an order or a pay change
        does not need a person in the finance pack. Default 0: every one does.
    off_limits: paths and services the agent must never read or contact (PSA #7812, GATE-DBENCH-02): an evaluator's
        tests, a harness's logs and control files, another tenant's data. A path matches itself and everything under
        it; an entry with a colon and no leading slash ("localhost:2280") is a service, an entry without either a
        host. A read or a listed path under one, a URL or host that is one, or the path written as a whole token in a
        command's or a tool's text (code included) sets reads_off_limits. Default none.
    contract: the task contract of this session (gate/contract.py): the tools, hosts, targets and paths the work may
        touch, declared before the agent reads any data. What an action touches outside it is the fact
        outside_contract. Default none: no contract.
    internal_sources: what the owner declares internal (PSA #7945): data the agent may work on and that must not leave.
        A path ("/srv/crm", "~/clients") matches itself and everything under it; an entry with a colon and no leading
        slash ("db.corp:5432") is a service; any other entry is a pattern on a tool name ("mcp__crm__*") or on a
        host ("*.corp.example"). An action that touches one sets reads_internal, and the session remembers it once
        that action ran. Default none: nothing is internal and the fields below stay empty.
    inside: the owner's own destinations (PSA #7945), where internal data may go: a mail domain or host
        ("acme.example", "*.acme.example"), an address ("legal@partner.example"), a URL prefix
        ("github.com/acme/*"), a channel ("#finance"), a tool ("mcp__sharepoint__*"), a command-line client ("gh").
        The hosts, services and tools of internal_sources are inside too, and so is this machine. Default none.
    """

    workspace: str = "."
    egress_hosts: list[str] = field(default_factory=list)
    environment: str = "dev"
    change_window: bool = False
    default_branches: list[str] = field(default_factory=lambda: ["main", "master"])
    git_remotes: list[str] = field(default_factory=lambda: ["github.com"])
    registries: dict[str, list[str]] = field(default_factory=lambda: {k: list(v) for k, v in DEFAULT_REGISTRIES.items()})
    extra_writable: list[str] = field(default_factory=lambda: ["/tmp"])
    home: str = ""
    workspaces_root: str = ""
    model_paths: list[str] = field(default_factory=lambda: list(DEFAULT_MODEL_PATHS))
    trusted_tools: list[str] = field(default_factory=list)
    collect_accounts: list[str] = field(default_factory=list)
    self_ids: list[str] = field(default_factory=list)
    declared_tools: list[str] = field(default_factory=list)
    assets: list[dict] = field(default_factory=list)
    money_limit: int = 0
    contract: dict | None = None
    off_limits: list[str] = field(default_factory=list)
    internal_sources: list[str] = field(default_factory=list)
    inside: list[str] = field(default_factory=list)

    @property
    def workspace_path(self) -> Path:
        return Path(self.workspace).expanduser().resolve()

    @property
    def home_path(self) -> Path:
        return Path(self.home).expanduser().resolve() if self.home else Path.home()

    def expand_home(self, p: str) -> str:
        """`~` and `~/...` as the agent's home; any other path unchanged."""
        if p == "~" or p.startswith("~/"):
            return str(self.home_path) + p[1:]
        return os.path.expanduser(p) if not self.home else p

    def all_egress(self) -> list[str]:
        hosts = list(self.egress_hosts) + list(self.git_remotes)
        for regs in self.registries.values():
            hosts.extend(regs)
        return sorted(set(h.lower() for h in hosts))

    def host_allowed(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        for pattern in self.all_egress():
            if pattern.startswith("*."):
                if host.endswith(pattern[1:]) or host == pattern[2:]:
                    return True
            elif host == pattern:
                return True
        return False

    def to_context(self) -> dict:
        return {
            "workspace": str(self.workspace_path),
            "egress_hosts": self.all_egress(),
            "egress_listed": bool(self.egress_hosts),   # the owner wrote a list of hosts (registries do not count)
            "environment": self.environment,
            "change_window": bool(self.change_window),
            "default_branches": list(self.default_branches),
            "assets_registered": bool(self.assets),
            "money_limit": int(self.money_limit or 0),
            "contract_declared": bool(self.contract),
            "off_limits_declared": bool(self.off_limits),
            "internal_declared": bool(self.internal_sources),
        }

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        data = json.loads(Path(path).read_text())
        return cls(**data)

    def writable_roots(self) -> Iterable[Path]:
        yield self.workspace_path
        for p in self.extra_writable:
            yield Path(p).expanduser().resolve()

