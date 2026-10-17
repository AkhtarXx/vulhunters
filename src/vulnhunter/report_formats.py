"""Interoperable security report exports."""

import hashlib
import re


def to_sarif(report: dict) -> dict:
    """Map evidence leads to SARIF 2.1.0 without upgrading their verification state."""
    rules = {}
    results = []
    for finding in report.get("findings", []):
        origin = str(finding.get("origin", "unknown"))
        title = str(finding["title"])
        rule = finding.get("rule_id")
        if not rule:
            slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60]
            rule = f"{origin}/{slug or 'finding'}"
        rule = str(rule)
        rules.setdefault(
            rule,
            {"id": rule, "name": title, "shortDescription": {"text": title}},
        )
        level = (
            "error"
            if finding["severity"] in {"critical", "high"}
            else "warning" if finding["severity"] == "medium" else "note"
        )
        item = {
            "ruleId": rule,
            "level": level,
            "message": {"text": str(finding["description"])},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(finding["file"])},
                        "region": {"startLine": int(finding["line"])},
                    }
                }
            ],
            "partialFingerprints": {"vulnhunters/v1": str(finding["id"])},
            "properties": {
                "findingId": finding["id"],
                "severity": finding["severity"],
                "origin": origin,
                "verification": finding.get("verification", "unverified"),
                "reviewDecision": finding.get("review", {}).get("decision", "pending"),
            },
        }
        results.append(item)
    run = {
        "tool": {
            "driver": {
                "name": "VulnHunters",
                "version": str(report.get("tool_versions", {}).get("vulnhunters", "unknown")),
                "rules": list(rules.values()),
            }
        },
        "results": results,
        "properties": {
            "auditStatus": report.get("status", "unknown"),
            "sourceSetSha256": hashlib.sha256(
                repr(sorted(report.get("source_sha256", {}).items())).encode()
            ).hexdigest(),
        },
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
