"""Apply explicit human triage decisions to immutable finding identities."""

from datetime import datetime, timezone

DECISIONS = {"confirmed", "false_positive", "needs_more_evidence"}


def apply_review(report: dict, payload: object) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get("decisions"), list):
        raise TypeError("Review input requires a decisions array")
    findings = {item["id"]: item for item in report.get("findings", [])}
    seen = set()
    for item in payload["decisions"]:
        if not isinstance(item, dict):
            raise TypeError("Review decisions must be objects")
        identifier = item.get("finding_id")
        if not isinstance(identifier, str) or identifier not in findings or identifier in seen:
            raise ValueError(f"Unknown or duplicate finding id: {identifier}")
        seen.add(identifier)
        decision = item.get("decision")
        if decision not in DECISIONS:
            raise ValueError(f"Invalid review decision for {identifier}")
        required = ["reviewer", "rationale"]
        if decision == "confirmed":
            required += ["impact", "preconditions", "likelihood", "severity_rationale"]
        for field in required:
            value = item.get(field)
            if not isinstance(value, str) or not value.strip() or len(value) > 4000:
                raise ValueError(f"Review {field} is required for {identifier}")
        findings[identifier]["review"] = {field: item[field].strip() for field in required} | {
            "decision": decision,
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
        }
    decisions = [item.get("review", {}).get("decision", "pending") for item in findings.values()]
    report["review"] = {
        "status": (
            "complete"
            if all(decision in {"confirmed", "false_positive"} for decision in decisions)
            else "pending"
        ),
        "pending": decisions.count("pending"),
        "confirmed": decisions.count("confirmed"),
        "false_positive": decisions.count("false_positive"),
        "needs_more_evidence": decisions.count("needs_more_evidence"),
        "note": "Human disposition does not itself verify an exploit or remediation.",
    }
    return report


def gate_report(
    report: dict, *, fail_on: str = "high", require_reviewed: bool = False
) -> list[str]:
    """Return concrete CI policy failures; callers choose the process exit code."""
    levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    if fail_on not in levels:
        raise ValueError("fail-on must be critical, high, medium, low or informational")
    failures = []
    if report.get("status") != "completed":
        failures.append("audit status is not completed")
    if require_reviewed and report.get("review", {}).get("status") != "complete":
        failures.append("finding review is incomplete")
    for finding in report.get("findings", []):
        if (
            finding.get("review", {}).get("decision") == "confirmed"
            and levels.get(finding.get("severity"), -1) >= levels[fail_on]
        ):
            failures.append(f"confirmed {finding['severity']} finding: {finding['id']}")
    return failures
