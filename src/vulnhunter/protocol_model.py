"""Explicit protocol assumptions supplied by the audit owner."""

import hashlib
import json
import re
from pathlib import Path

MANIFEST_NAME = "audit-manifest.json"
MAX_MANIFEST_BYTES = 20_000
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,79}$")


def _text(value: object, field: str, limit: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"Manifest {field} must be non-empty text up to {limit} characters")
    return value.strip()


def _strings(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 100:
        raise ValueError(f"Manifest {field} must contain 1-100 entries")
    return [_text(item, field) for item in value]


def load_protocol_model(root: Path, chain: str, sources: dict[str, str]) -> dict:
    """Validate a small, reviewable model without inferring business invariants."""
    path = root / MANIFEST_NAME
    if not path.exists():
        return {
            "status": "missing",
            "reason": f"{MANIFEST_NAME} is absent; assets, actors, trust boundaries and invariants are undeclared",
        }
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError("Manifest path escapes the project or is not a file")
    raw = resolved.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError(f"Manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Manifest is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("Manifest requires schema_version 1")
    if _text(value.get("chain"), "chain") != chain:
        raise ValueError("Manifest chain does not match the audit --chain value")
    entrypoints = _strings(value.get("entrypoints"), "entrypoints")
    if any(item not in sources for item in entrypoints):
        raise ValueError("Manifest entrypoints must be files in the audited scope")
    invariants = value.get("invariants")
    if not isinstance(invariants, list) or not invariants or len(invariants) > 100:
        raise ValueError("Manifest invariants must contain 1-100 entries")
    normalized = []
    seen = set()
    for item in invariants:
        if not isinstance(item, dict):
            raise TypeError("Manifest invariant entries must be objects")
        identifier = _text(item.get("id"), "invariant id", 80)
        if not _IDENTIFIER.fullmatch(identifier) or identifier in seen:
            raise ValueError("Manifest invariant ids must be unique identifiers")
        seen.add(identifier)
        test = item.get("forge_test")
        normalized.append(
            {
                "id": identifier,
                "statement": _text(item.get("statement"), "invariant statement", 1000),
                "forge_test": _text(test, "forge_test", 200) if test is not None else None,
            }
        )
    model = {
        "schema_version": 1,
        "protocol": _text(value.get("protocol"), "protocol"),
        "chain": chain,
        "entrypoints": entrypoints,
        "assets": _strings(value.get("assets"), "assets"),
        "actors": _strings(value.get("actors"), "actors"),
        "trust_boundaries": _strings(value.get("trust_boundaries"), "trust_boundaries"),
        "invariants": normalized,
    }
    return {
        "status": "declared",
        "path": MANIFEST_NAME,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "model": model,
        "note": "Declarations are audit assumptions, not independently verified facts.",
    }
