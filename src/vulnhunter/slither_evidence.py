"""Turn Slither detector output into bounded, in-scope audit evidence."""

import hashlib
from pathlib import Path

_IMPACT = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "optimization": "informational",
}


def _location(project: Path, sources: dict[str, str], detector: dict) -> tuple[str, int] | None:
    for element in detector.get("elements", []):
        mapping = element.get("source_mapping", {})
        if not isinstance(mapping, dict):
            continue
        filename = mapping.get("filename_absolute") or mapping.get("filename_relative")
        if not isinstance(filename, str) or not filename:
            continue
        candidate = Path(filename)
        try:
            resolved = (candidate if candidate.is_absolute() else project / candidate).resolve()
            relative = resolved.relative_to(project.resolve()).as_posix()
        except (OSError, ValueError):
            continue
        if relative not in sources:
            continue
        lines = mapping.get("lines", [])
        if not isinstance(lines, list):
            continue
        for line in lines:
            if type(line) is int and 1 <= line <= len(sources[relative].splitlines()):
                return relative, line
    return None


def normalize_slither(project: Path, sources: dict[str, str], detectors: list[dict]) -> dict:
    """Keep only detector locations provably inside the immutable source scope."""
    findings = []
    unmapped = 0
    seen = set()
    for detector in detectors:
        if not isinstance(detector, dict):
            unmapped += 1
            continue
        location = _location(project, sources, detector)
        if location is None:
            unmapped += 1
            continue
        path, line = location
        rule = str(detector.get("check") or "unknown")[:120]
        description = str(detector.get("description") or "Slither detector signal")[:2000].strip()
        digest = hashlib.sha256(
            f"slither\0{rule}\0{path}\0{line}\0{description}".encode()
        ).hexdigest()[:12]
        if digest in seen:
            continue
        seen.add(digest)
        confidence = str(detector.get("confidence") or "Unknown")[:40]
        impact = str(detector.get("impact") or "Informational")[:40]
        findings.append(
            {
                "id": f"VH-{digest}",
                "title": f"Slither: {rule}",
                "severity": _IMPACT.get(impact.lower(), "informational"),
                "file": path,
                "line": line,
                "description": description,
                "impact": f"Slither rates this signal {impact}; actual impact needs review.",
                "recommendation": "Triage the detector evidence, confirm reachability and impact, then address the root cause.",
                "evidence": sources[path].splitlines()[line - 1].strip()[:500],
                "origin": "slither",
                "rule_id": rule,
                "confidence": confidence.lower(),
                "verification": "unverified",
            }
        )
    return {"findings": findings, "unmapped_count": unmapped}
