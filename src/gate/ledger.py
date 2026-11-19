"""The decision log as a hash chain (PSA prior-art review: a tamper-evident record, as Watchlight's signed,
hash-chained record).

Every line carries `prev`, the `hash` of the line before it (64 zeros for the first line; the SHA-256 of the raw text
for a line written before the chain existed), and its own `hash`: the SHA-256 of `prev` and of the entry's canonical
JSON. Changing, removing or reordering any line breaks every hash after it. With a key in `GATE_LOG_HMAC_KEY` each line
also carries `mac`, an HMAC-SHA256 of its hash, so a log rewritten from scratch without the key is told apart.
`gate log verify <file>` checks a log.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

GENESIS = "0" * 64
_CHAIN_FIELDS = ("prev", "hash", "mac")


def _key() -> bytes | None:
    k = os.environ.get("GATE_LOG_HMAC_KEY", "")
    return k.encode() if k else None


def _body(entry: dict) -> str:
    return json.dumps({k: v for k, v in entry.items() if k not in _CHAIN_FIELDS}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False)


def _hash(prev: str, entry: dict) -> str:
    return hashlib.sha256((prev + "\n" + _body(entry)).encode()).hexdigest()


def _link_of(raw: str) -> str:
    """The hash the next line must name as `prev`."""
    try:
        e = json.loads(raw)
        if isinstance(e, dict) and isinstance(e.get("hash"), str):
            return e["hash"]
    except json.JSONDecodeError:
        pass
    return hashlib.sha256(raw.encode()).hexdigest()


class ChainedLog:
    """Appends entries to a JSON-lines file as a hash chain, each written and fsynced at once."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._last: str | None = None

    def _tail(self) -> str:
        if self._last is None:
            last = GENESIS
            if self.path.exists():
                with open(self.path, "rb") as f:
                    f.seek(0, 2)
                    size = f.tell()
                    f.seek(max(0, size - 1_000_000))
                    lines = [x for x in f.read().decode("utf-8", "replace").split("\n") if x.strip()]
                if lines:
                    last = _link_of(lines[-1])
            self._last = last
        return self._last

    def append(self, entry: dict) -> dict:
        prev = self._tail()
        e = {k: v for k, v in entry.items() if k not in _CHAIN_FIELDS}
        e["prev"] = prev
        e["hash"] = _hash(prev, e)
        key = _key()
        if key:
            e["mac"] = hmac.new(key, e["hash"].encode(), hashlib.sha256).hexdigest()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._last = e["hash"]
        return e


def verify(path: str | Path, key: bytes | None = None) -> dict:
    """Check a log. Returns {"ok", "lines", "chained", "unchained", "first_bad_line", "reason"}."""
    prev = GENESIS
    chained = unchained = 0
    n = 0
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            raw = raw.rstrip("\n")
            if not raw.strip():
                continue
            try:
                e = json.loads(raw)
            except json.JSONDecodeError:
                return {"ok": False, "lines": n, "chained": chained, "unchained": unchained, "first_bad_line": n,
                        "reason": "not JSON"}
            if not isinstance(e, dict) or "hash" not in e:
                if chained:
                    return {"ok": False, "lines": n, "chained": chained, "unchained": unchained,
                            "first_bad_line": n, "reason": "an unchained line after the chain started"}
                unchained += 1
                prev = hashlib.sha256(raw.encode()).hexdigest()
                continue
            if e.get("prev") != prev:
                return {"ok": False, "lines": n, "chained": chained, "unchained": unchained, "first_bad_line": n,
                        "reason": "prev does not match the line before (a line was changed, removed or moved)"}
            if _hash(prev, e) != e["hash"]:
                return {"ok": False, "lines": n, "chained": chained, "unchained": unchained, "first_bad_line": n,
                        "reason": "hash does not match the content (the line was changed)"}
            if key is not None:
                want = hmac.new(key, e["hash"].encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(want, str(e.get("mac", ""))):
                    return {"ok": False, "lines": n, "chained": chained, "unchained": unchained,
                            "first_bad_line": n, "reason": "mac does not match (written without the key)"}
            chained += 1
            prev = e["hash"]
    return {"ok": True, "lines": n, "chained": chained, "unchained": unchained, "first_bad_line": None,
            "reason": "", "last_hash": prev}
