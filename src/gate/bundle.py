"""Signed rule-pack bundles (PSA prior-art review: the maintained packs delivered into a customer's perimeter as
versioned files).

A bundle is a directory of `.cedar` packs plus `manifest.json` (format, packs version, the engine version it needs,
the SHA-256 of every pack file) and `manifest.sig` (an Ed25519 signature of the manifest's bytes, base64). When a
packs directory holds a manifest, every pack file must match it and no unlisted pack may be present. When a public key
is configured (`GATE_PACKS_PUBKEY`, base64 of the 32-byte raw key, or `set_packs_pubkey`), a directory without a valid
signature is refused. Signing needs the optional `cryptography` package (`pip install "splabs-gate[signing]"`);
checking a signature without it is refused, never skipped.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

FORMAT = 1


class BundleError(ValueError):
    """A packs directory that does not match its manifest or its signature."""


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in str(v).split(".") if x.isdigit())


def make(directory: str | Path, packs_version: str, engine_min: str, private_key_b64: str | None = None) -> dict:
    """Write manifest.json (and manifest.sig when a private key is given) for the packs in a directory."""
    d = Path(directory)
    files = {p.name: _sha(p) for p in sorted(d.glob("*.cedar"))}
    if not files:
        raise BundleError(f"no .cedar files in {d}")
    manifest = {"format": FORMAT, "packs_version": packs_version, "engine_min": engine_min, "files": files}
    raw = json.dumps(manifest, sort_keys=True, indent=1).encode()
    (d / "manifest.json").write_bytes(raw)
    if private_key_b64:
        (d / "manifest.sig").write_text(base64.b64encode(_sign(raw, private_key_b64)).decode() + "\n")
    return manifest


def _sign(data: bytes, private_key_b64: str) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64)).sign(data)


def _verify_sig(data: bytes, sig_b64: str, public_key_b64: str) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as e:
        raise BundleError("a packs public key is configured but the 'cryptography' package is not installed: "
                          "pip install \"splabs-gate[signing]\"") from e
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64)).verify(base64.b64decode(sig_b64), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def keypair() -> tuple[str, str]:
    """A new Ed25519 key pair as (private, public), base64 of the raw 32-byte keys."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def check(directory: str | Path, public_key_b64: str | None, engine_version: str) -> dict | None:
    """Check a packs directory against its manifest and signature. Returns the manifest, or None when the directory
    has no manifest and no key is configured (an unsigned directory, as before bundles existed)."""
    d = Path(directory)
    mf = d / "manifest.json"
    if not mf.is_file():
        if public_key_b64:
            raise BundleError(f"{d}: a packs public key is configured but the directory has no manifest.json")
        return None
    raw = mf.read_bytes()
    if public_key_b64:
        sig = d / "manifest.sig"
        if not sig.is_file() or not _verify_sig(raw, sig.read_text().strip(), public_key_b64):
            raise BundleError(f"{d}: manifest.sig is missing or does not match the configured packs public key")
    manifest = json.loads(raw)
    files = manifest.get("files") or {}
    present = {p.name for p in d.glob("*.cedar")}
    extra = sorted(present - set(files))
    if extra:
        raise BundleError(f"{d}: pack files not in the manifest: {', '.join(extra)}")
    for name, digest in files.items():
        p = d / name
        if not p.is_file() or _sha(p) != digest:
            raise BundleError(f"{d}: {name} is missing or does not match the manifest")
    need = manifest.get("engine_min")
    if need and _version_tuple(engine_version) < _version_tuple(need):
        raise BundleError(f"{d}: these packs need engine {need} or later, this is {engine_version}")
    return manifest


def configured_pubkey() -> str | None:
    return os.environ.get("GATE_PACKS_PUBKEY", "").strip() or None
