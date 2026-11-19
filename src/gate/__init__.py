"""gate: a deterministic gate for the actions of AI agents.

Every action an agent proposes is normalised into a record, checked against Cedar rules the owner wrote, and
allowed, denied or held for a person. Same input, same rules, same answer.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .checker import ALLOW, CONFIRM, DENY, Decision, PolicySet
from .config import Config
from .ledger import ChainedLog
from .bundle import BundleError, check as check_bundle, configured_pubkey
from .contract import clean as clean_contract, outside as contract_outside
from .normalize import normalize
from .session import Session

__all__ = ["Gate", "Config", "Session", "Decision", "PolicySet", "ALLOW", "DENY", "CONFIRM", "PACKS_DIR", "pack_paths",
           "packs_dir", "set_packs_dir", "PacksNotInstalled", "set_packs_pubkey", "BundleError"]
__version__ = "0.1.69"

# The engine ships no rules. The maintained packs (common, coding, ops, strict, harness) are served by the hosted
# gate; a directory holding them, or your own, is named with GATE_PACKS_DIR or set_packs_dir().
PACKS_DIR = Path(__file__).parent / "packs"
PACKS = ("coding", "ops", "strict", "harness", "industrial", "building", "finance", "gui", "scope")
_packs_dir: Path | None = None


class PacksNotInstalled(ValueError):
    """A pack was asked for and its file is not in the packs directory."""


def set_packs_dir(path: str | Path | None) -> None:
    """Where pack files are read from: <dir>/common.cedar and <dir>/<pack>.cedar. None goes back to the default."""
    global _packs_dir
    _packs_dir = Path(path) if path else None


def packs_dir() -> Path:
    if _packs_dir is not None:
        return _packs_dir
    env = os.environ.get("GATE_PACKS_DIR", "").strip()
    return Path(env) if env else PACKS_DIR


def pack_paths(names: list[str] | str, directory: str | Path | None = None) -> list[Path]:
    if isinstance(names, str):
        names = [n.strip() for n in names.split(",") if n.strip()]
    d = Path(directory) if directory else packs_dir()
    paths = [d / "common.cedar"]
    for n in names:
        if n not in PACKS:
            raise ValueError(f"unknown pack {n!r}; available: {', '.join(PACKS)}")
        paths.append(d / f"{n}.cedar")
    missing = [p.name for p in paths if not p.is_file()]
    if missing:
        raise PacksNotInstalled(
            f"rule pack files not found in {d}: {', '.join(missing)}. This package ships the engine without rules: "
            "use the hosted gate for the maintained packs, set GATE_PACKS_DIR to a directory that holds them, or "
            "load your own rules with Gate(PolicySet.from_paths([...])).")
    _check_bundle(d)
    return paths


_bundle_checked: dict = {}


def set_packs_pubkey(key_b64: str | None) -> None:
    """The Ed25519 public key (base64 of the raw 32 bytes) the packs directory's signature must match; None goes back
    to GATE_PACKS_PUBKEY."""
    global _packs_pubkey
    _packs_pubkey = key_b64 or None
    _bundle_checked.clear()


_packs_pubkey: str | None = None


def _check_bundle(d: Path) -> None:
    """A packs directory with a manifest must match it; with a public key configured it must be signed (bundle.py)."""
    key = _packs_pubkey or configured_pubkey()
    mf = d / "manifest.json"
    stamp = (str(d), key, mf.stat().st_mtime_ns if mf.is_file() else None,
             tuple(sorted((p.name, p.stat().st_mtime_ns) for p in d.glob("*.cedar"))))
    if _bundle_checked.get(str(d)) == stamp:
        return
    check_bundle(d, key, __version__)
    _bundle_checked[str(d)] = stamp


class Gate:
    def __init__(self, policies: PolicySet, config: Config | None = None, log_path: str | Path | None = None):
        self.policies = policies
        self.config = config or Config()
        self._contract = clean_contract(self.config.contract)
        self.log_path = Path(log_path) if log_path else None
        self._ledger = None

    @classmethod
    def from_pack(cls, packs: list[str] | str = "coding", config: Config | None = None,
                  extra_policies: list[str | Path] | None = None, log_path: str | Path | None = None) -> "Gate":
        paths = pack_paths(packs) + [Path(p) for p in (extra_policies or [])]
        return cls(PolicySet.from_paths(paths), config, log_path)

    def new_session(self) -> Session:
        s = Session()
        s.system_values = self.config.all_egress() + [str(self.config.workspace_path)]
        s.trusted_tools = list(self.config.trusted_tools)
        return s

    def check(self, action: dict, session: Session | None = None, agent: str = "agent",
              agent_attrs: dict | None = None, session_id: str = "") -> Decision:
        session = session if session is not None else self.new_session()
        action_type = str(action.get("type", "unknown"))
        record = normalize(action, self.config)
        facts = session.facts(record)
        facts["outside_contract"] = contract_outside(record, self._contract, session.contract_widened)
        facts["contract_operations"] = sorted((self._contract or {}).get("operations", []))
        context = {"n": record, "facts": facts, "config": self.config.to_context()}
        decision = self.policies.evaluate(action_type, agent, context, agent_attrs)
        if decision.outcome == ALLOW and (record["reads_secret"] or record["tool_reads_secret"]):
            session.secret_read = True
        if decision.outcome == ALLOW:
            session.note_done(record)
        if decision.outcome == DENY:
            session.denials += 1
        elif decision.outcome == CONFIRM:
            session.holds += 1
        decision.record = {"action": action, "normalized": record, "facts": facts}
        if self.log_path:
            self._log(decision, agent, session_id)
        return decision

    def check_plan(self, plan: dict, session: Session | None = None, agent: str = "agent"):
        """Decide a compound shell line or a list of actions step by step (gate.plan, PSA #7814): which steps can
        run, which wait for a person, which are refused, and which are blocked because they need a step that did not
        pass. The session is not changed; send each step that runs through check() as usual."""
        from .plan import check_plan
        return check_plan(self, plan, session=session, agent=agent)

    def approve(self, decision: Decision, session: Session) -> None:
        """Record that a person approved a held action (it will be executed by the caller)."""
        normalized = decision.record.get("normalized", {})
        if decision.outcome == CONFIRM and (normalized.get("reads_secret") or normalized.get("tool_reads_secret")):
            session.secret_read = True
        if decision.outcome == CONFIRM:
            session.note_done(normalized)
            session.widen(decision.record.get("facts", {}).get("outside_contract", []))
        name = str(decision.record.get("action", {}).get("name", ""))
        if decision.outcome == CONFIRM and session.tool_changed(name):
            session.repin(name)

    def _log(self, decision: Decision, agent: str, session_id: str) -> None:
        # a hash chain (gate/ledger.py): any line changed, removed or moved afterwards is found by `gate log verify`
        if self._ledger is None or self._ledger.path != self.log_path:
            self._ledger = ChainedLog(self.log_path)
        self._ledger.append({"ts": time.time(), "session": session_id, "agent": agent, "outcome": decision.outcome,
                             "rules": decision.rules, "action": decision.record["action"],
                             "normalized": decision.record["normalized"], "facts": decision.record["facts"],
                             "errors": decision.errors})
