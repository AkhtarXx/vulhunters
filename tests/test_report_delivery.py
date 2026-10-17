"""Review decisions and machine-readable delivery retain provenance."""

import json

import pytest
from typer.testing import CliRunner

from vulnhunter.audit_engine import save_report
from vulnhunter.report_formats import to_sarif
from vulnhunter.review import apply_review, gate_report
from vulnhunter.unified_cli import app


def report():
    return {
        "schema_version": 2,
        "status": "completed",
        "protocol": "Vault",
        "provider": "claude",
        "files": ["src/Vault.sol"],
        "source_sha256": {"src/Vault.sol": "abc"},
        "tool_versions": {"vulnhunters": "2.1.0"},
        "checks": {},
        "findings": [
            {
                "id": "VH-abc",
                "title": "Unsafe withdrawal",
                "severity": "high",
                "file": "src/Vault.sol",
                "line": 10,
                "description": "Withdrawal can reenter",
                "impact": "Funds at risk",
                "recommendation": "Move state update before call",
                "origin": "slither",
                "rule_id": "reentrancy-eth",
                "verification": "unverified",
            }
        ],
        "review": {"status": "pending"},
    }


def test_review_requires_rationale_and_does_not_claim_exploit_verification():
    value = report()
    with pytest.raises(ValueError, match="preconditions"):
        apply_review(
            value,
            {
                "decisions": [
                    {
                        "finding_id": "VH-abc",
                        "decision": "confirmed",
                        "reviewer": "A. Reviewer",
                        "rationale": "Reachable external call",
                        "impact": "Funds at risk",
                    }
                ]
            },
        )
    apply_review(
        value,
        {
            "decisions": [
                {
                    "finding_id": "VH-abc",
                    "decision": "confirmed",
                    "reviewer": "A. Reviewer",
                    "rationale": "Reachable external call",
                    "impact": "Funds at risk",
                    "preconditions": "Attacker can deposit and call withdraw",
                    "likelihood": "Medium",
                    "severity_rationale": "Potential loss of pooled funds",
                }
            ]
        },
    )
    assert value["review"]["status"] == "complete"
    assert value["findings"][0]["verification"] == "unverified"
    assert gate_report(value, fail_on="high", require_reviewed=True) == [
        "confirmed high finding: VH-abc"
    ]


def test_sarif_export_and_atomic_sibling_files(tmp_path):
    value = report()
    sarif = to_sarif(value)
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "reentrancy-eth"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    assert result["properties"]["verification"] == "unverified"
    path = tmp_path / "report.json"
    save_report(value, path)
    assert json.loads(path.with_suffix(".sarif").read_text())["version"] == "2.1.0"
    assert "Unsafe withdrawal" in path.with_suffix(".md").read_text()


def test_gate_requires_complete_audit_and_review_when_requested():
    value = report()
    value["status"] = "partial"
    assert gate_report(value, require_reviewed=True) == [
        "audit status is not completed",
        "finding review is incomplete",
    ]


def test_review_and_gate_cli_round_trip(tmp_path):
    value = report()
    path = tmp_path / "report.json"
    save_report(value, path)
    decisions = tmp_path / "decisions.json"
    decisions.write_text(
        json.dumps(
            {
                "decisions": [
                    {
                        "finding_id": "VH-abc",
                        "decision": "false_positive",
                        "reviewer": "Test reviewer",
                        "rationale": "Synthetic fixture has no vulnerable deployed contract",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    reviewed = runner.invoke(app, ["review", str(path), str(decisions)])
    assert reviewed.exit_code == 0, reviewed.output
    assert json.loads(path.read_text())["review"]["status"] == "complete"
    gated = runner.invoke(app, ["gate", str(path), "--require-reviewed"])
    assert gated.exit_code == 0, gated.output
