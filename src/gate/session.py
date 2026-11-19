"""Session state and the facts the rules may read besides the action itself."""

from __future__ import annotations

import fnmatch
import functools
import hashlib
import json
import re
from dataclasses import dataclass, field


_PACKAGE_NAME_RE = re.compile(r"^(@?[a-z0-9][a-z0-9._-]*(?:/[a-z0-9._-]+)?)(?:\[[^\]]*\])?\s*(?:===|==|>=|<=|~=|!=|<|>|@|\^|~).*$")


def _norm(v: str) -> str:
    return v.strip().strip("'\"").rstrip("/").lower()


@dataclass
class Session:
    """What happened so far in one agent session.

    The caller feeds it the user's messages and what each tool returned. Provenance is computed by exact and
    normalised string match: a value is "user" if it appears in a user message, "system" if the operator
    configuration names it, "tool_output" if it first appears in something a tool returned, "model" if it
    appears nowhere before the model wrote it.
    """

    user_messages: list[str] = field(default_factory=list)
    tool_outputs: dict[str, str] = field(default_factory=dict)
    system_values: list[str] = field(default_factory=list)
    trusted_tools: list[str] = field(default_factory=list)
    # The definition of each tool the agent was given (its description and its parameters), as a fingerprint: the
    # first one seen is the pin, the latest one seen is the current. A tool whose current definition differs from
    # its pin changed during the session (a "rug pull": a server rewrites a tool after it was approved).
    tool_pins: dict[str, str] = field(default_factory=dict)
    tool_defs: dict[str, str] = field(default_factory=dict)
    secret_read: bool = False
    # a payee's bank details were changed in this session (allowed or approved), and how many machine writes each
    # asset received (allowed or approved): segregation of duties and write caps (v0.1.56, PSA #7802)
    bank_changed: bool = False
    asset_writes: dict[str, int] = field(default_factory=dict)
    denials: int = 0
    holds: int = 0

    def observe_tools(self, definitions, server: str = "") -> None:
        """The tool definitions the agent was given, at the start and whenever they are listed again (MCP
        tools/list, an updated tool list). Accepts MCP ({name, description, inputSchema}), OpenAI ({type: function,
        function: {name, description, parameters}}) and Anthropic ({name, description, input_schema}) shapes, a list
        or a JSON string of a list. `server` prefixes bare MCP names as the harness calls them (mcp__server__name)."""
        if isinstance(definitions, str):
            try:
                definitions = json.loads(definitions or "[]")
            except json.JSONDecodeError:
                return
        if isinstance(definitions, dict):
            definitions = definitions.get("tools", [definitions])
        for d in definitions or []:
            name, fp = tool_fingerprint(d)
            if not name:
                continue
            if server and not name.startswith("mcp__"):
                name = f"mcp__{server}__{name}"
            self.tool_pins.setdefault(name, fp)
            self.tool_defs[name] = fp

    def tool_changed(self, name: str) -> bool:
        return bool(name) and name in self.tool_pins and self.tool_defs.get(name, self.tool_pins[name]) != self.tool_pins[name]

    def repin(self, name: str) -> None:
        """A person approved a call to a tool whose definition changed: its current definition becomes the pin."""
        if name in self.tool_defs:
            self.tool_pins[name] = self.tool_defs[name]

    def note_done(self, record: dict) -> None:
        """An action was allowed or approved: remember what the domain facts need."""
        effects = set(record.get("effects", []))
        if "bank_details" in effects:
            self.bank_changed = True
        if effects & {"setpoint", "actuate", "motion", "mode", "program", "safety", "physical_access"}:
            for a in record.get("assets", []):
                self.asset_writes[a] = self.asset_writes.get(a, 0) + 1

    def observe_user(self, text: str) -> None:
        self.user_messages.append(text)

    def observe_tool_output(self, tool_id: str, text: str) -> None:
        self.tool_outputs[tool_id] = text

    def provenance(self, value: str, package: bool = False, exact: bool = False) -> str:
        v = _norm(value)
        if not v:
            return "model"
        variants = {v}
        if package:
            # a package is known by its name: a version, extras or an index marker attached to it do not change
            # where the name came from
            m = _PACKAGE_NAME_RE.match(v)
            if m and m.group(1) != v:
                variants.add(m.group(1))
        if "/" in v and "://" not in v and not exact:
            # a path is known by its file name too (`units.py` for `shipcalc/units.py`); a URL is not: the last
            # segment of a planted link (`donate.example/<site name>`) would otherwise match the site the user named
            variants.add(v.rsplit("/", 1)[-1])
        if any(_contains(m, x) for m in self.user_messages for x in variants):
            return "user"
        if any(_contains(s, x) for s in self.system_values for x in variants):
            return "system"
        trusted = []
        for tool_id, text in self.tool_outputs.items():
            if self._trusted(tool_id):
                trusted.append(text)
                continue
            if any(_contains(text, x) for x in variants):
                return "tool_output"          # outside data wins over a trusted record that also holds the value
        if any(_contains(text, x) for text in trusted for x in variants):
            return "trusted"
        return "model"

    def _trusted(self, tool_id: str) -> bool:
        name = str(tool_id).split(":", 1)[0]
        return any(fnmatch.fnmatch(name, p) for p in self.trusted_tools)

    def facts(self, record: dict) -> dict:
        values = set(record["hosts"]) | set(record["urls"]) | set(record["packages"])
        values |= {p for p in record["paths"] if p}
        values |= set(record.get("tool_targets", []))
        values |= set(record.get("tool_send_targets", []))
        values |= set(record.get("payment_targets", []))
        values |= set(record.get("tool_arg_values", []))
        values |= set(record.get("tool_secret_values", [])) | set(record.get("tool_bulk_values", []))
        values |= set(record.get("tool_admin_urls", []))
        values |= set(record.get("bank_values", []))
        packages = set(record["packages"])
        prov = {v: self.provenance(v, package=v in packages) for v in sorted(values)}
        for v in record.get("tool_admin_urls", []):
            # an admin page counts as the user's only when the user named the page, not a word at its end
            # ("list recent transactions" does not name /admin/transactions)
            prov[v] = self.provenance(v, exact=True)
        if "all" in prov and prov["all"] != "user" and any(_ALL_WORDS_RE.search(m) for m in self.user_messages):
            # the mass scope of a tool call (a bare *, delete_all_files) is what a person asks for with these words
            prov["all"] = "user"
        return {
            "from_user": sorted(k for k, s in prov.items() if s == "user"),
            "from_system": sorted(k for k, s in prov.items() if s == "system"),
            "from_tool_output": sorted(k for k, s in prov.items() if s == "tool_output"),
            "from_trusted": sorted(k for k, s in prov.items() if s == "trusted"),
            "from_model": sorted(k for k, s in prov.items() if s == "model"),
            "git_remote_not_from_user": any(self.provenance(u) != "user" for u in record.get("git_remote_urls", [])),
            "secret_read_in_session": self.secret_read,
            "bank_changed_in_session": self.bank_changed,
            "asset_writes_in_session": max([self.asset_writes.get(a, 0) for a in record.get("assets", [])] or [0]),
            "tool_definition_changed": self.tool_changed(record.get("tool_name", "")),
            "denials_in_session": self.denials,
            "holds_in_session": self.holds,
        }


_ALL_WORDS_RE = re.compile(r"\b(?:all|every|everyone|everybody|everything|entire)\b", re.IGNORECASE)


_NUMBER_RE = re.compile(r"[$\u20ac\u00a3]?\d{1,3}(?:[,'\u00a0 ]\d{3})+(?:\.\d+)?|[$\u20ac\u00a3]?\d+(?:\.\d+)?")
_GROUP_SEP_RE = re.compile(r"(?<=\d)[,'\u00a0 ](?=\d{3}(?!\d))")
_PUNCT_RE = re.compile(r"[^\w@]+")


@functools.lru_cache(maxsize=256)
def _hay_forms(haystack: str) -> tuple[str, str, str]:
    """A text lower-cased, with digit-group separators removed, and with punctuation turned to spaces (computed once
    per text, not once per value checked against it)."""
    hay = haystack.lower()
    return hay, _GROUP_SEP_RE.sub("", hay), _PUNCT_RE.sub(" ", hay)


def _contains(haystack: str, needle: str) -> bool:
    if len(needle) < 3:
        return False
    hay, hay_digits, hay_words = _hay_forms(haystack)
    if re.search(r"(?<![\w.-])" + re.escape(needle) + r"(?![\w-])", hay) is not None:
        return True
    if _NUMBER_RE.fullmatch(needle):
        # an amount is the same number however its thousands are written: "50000" and "$50,000" (v0.1.51,
        # GATE-ADAPT-01: update_invoice new_amount="50000" from an e-mail that said "$50,000" read as invented)
        n = _GROUP_SEP_RE.sub("", needle).lstrip("$\u20ac\u00a3")
        if len(n) >= 3 and re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", hay_digits):
            return True
        return False
    if " " in needle.strip() or "," in needle:
        # a value of several words is the same value whatever the punctuation between them: "123 Attacker Way, Drop
        # City" and "123 Attacker Way\nDrop City" (v0.1.51, GATE-ADAPT-01: a shipping address planted in an e-mail
        # without the comma read as invented)
        n = _PUNCT_RE.sub(" ", needle).strip()
        if len(n) >= 6 and " " in n:
            return re.search(r"(?<!\w)" + re.escape(n) + r"(?!\w)", hay_words) is not None
    return False


def tool_fingerprint(d) -> tuple[str, str]:
    """(name, fingerprint) of one tool definition: a hash of its description and its parameters, key order and
    whitespace aside, so the same definition always gives the same fingerprint."""
    if not isinstance(d, dict):
        return "", ""
    if isinstance(d.get("function"), dict):
        d = d["function"]
    name = str(d.get("name") or "")
    params = d.get("inputSchema", d.get("input_schema", d.get("parameters", {})))
    body = json.dumps({"description": " ".join(str(d.get("description") or "").split()), "parameters": params},
                      sort_keys=True, ensure_ascii=False, default=str)
    return name, hashlib.sha256(body.encode()).hexdigest()
