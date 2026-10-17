"""Regression tests for the active audit and report path."""

import json
import sys

import pytest

from vulnhunter.audit_engine import load_scope, run_audit, save_report, static_findings
from vulnhunter.orchestrator import AutonomousOrchestrator
from vulnhunter.poc_verifier import validate_proof_source, verify_poc
from vulnhunter.process import ProcessResult
from vulnhunter.providers import ProviderError
from vulnhunter.slither_evidence import normalize_slither

SOURCE = """pragma solidity ^0.8.20;
contract Bank {
    mapping(address => uint) public balances;
    function withdraw() external {
        (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""


class FakeProvider:
    name = "fake"

    async def generate(self, prompt, schema):
        assert "FILE src/Bank.sol" in prompt
        assert schema["type"] == "object"
        return {
            "findings": [
                {
                    "title": "Reentrancy",
                    "severity": "high",
                    "file": "src/Bank.sol",
                    "line": 4,
                    "description": "External call before balance reset",
                    "impact": "Repeated withdrawal",
                    "recommendation": "Reset first",
                }
            ]
        }


class BrokenProvider:
    name = "broken"

    async def generate(self, prompt, schema):
        raise ProviderError("quota exhausted")


@pytest.fixture
def project(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/Bank.sol").write_text(SOURCE, encoding="utf-8")
    return tmp_path


@pytest.mark.asyncio
async def test_report_has_real_finding_and_unverified_state(project):
    report = await run_audit(project, FakeProvider(), slither=False)
    assert report["status"] == "partial"
    assert report["summary"]["findings"] == 1
    assert report["summary"]["verified_exploits"] == 0
    assert report["findings"][0]["verification"] == "unverified"
    assert report["findings"][0]["origin"] == "ai"
    assert report["findings"][0]["evidence"].startswith("function withdraw")
    destination = project / "report.json"
    save_report(report, destination)
    assert json.loads(destination.read_text())["findings"][0]["file"] == "src/Bank.sol"
    assert "Reentrancy" in destination.with_suffix(".md").read_text()


@pytest.mark.asyncio
async def test_provider_error_does_not_become_clean_report(project):
    report = await run_audit(project, BrokenProvider(), slither=False)
    assert report["status"] == "failed"
    assert "quota exhausted" in report["error"]


@pytest.mark.asyncio
async def test_changed_source_during_analysis_fails_report(project):
    class MutatingProvider(FakeProvider):
        async def generate(self, prompt, schema):
            result = await super().generate(prompt, schema)
            (project / "src/Bank.sol").write_text(SOURCE + "// changed", encoding="utf-8")
            return result

    report = await run_audit(project, MutatingProvider(), slither=False)
    assert report["status"] == "failed"
    assert "source changed" in report["error"].lower()


def test_slither_evidence_stays_in_scope(project):
    sources = {"src/Bank.sol": SOURCE}
    detector = {
        "check": "reentrancy-eth",
        "impact": "High",
        "confidence": "Medium",
        "description": "External call can reenter",
        "elements": [
            {
                "source_mapping": {
                    "filename_absolute": str(project / "src/Bank.sol"),
                    "lines": [5, 6],
                }
            }
        ],
    }
    foreign = {
        **detector,
        "elements": [
            {
                "source_mapping": {
                    "filename_absolute": str(project.parent / "other.sol"),
                    "lines": [1],
                }
            }
        ],
    }
    result = normalize_slither(project, sources, [detector, detector, foreign])
    assert len(result["findings"]) == 1
    assert result["unmapped_count"] == 1
    finding = result["findings"][0]
    assert finding["origin"] == "slither"
    assert finding["severity"] == "high"
    assert finding["file"] == "src/Bank.sol"
    assert finding["line"] == 5
    assert finding["evidence"].startswith("(bool ok,")


@pytest.mark.asyncio
async def test_completed_audit_includes_slither_evidence(project, monkeypatch):
    from vulnhunter import audit_engine

    async def fake_slither(root, sources, timeout=120):
        return {
            "status": "completed",
            "count": 1,
            "findings": normalize_slither(
                root,
                sources,
                [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "External call can reenter",
                        "elements": [
                            {"source_mapping": {"filename_relative": "src/Bank.sol", "lines": [5]}}
                        ],
                    }
                ],
            )["findings"],
        }

    monkeypatch.setattr(audit_engine, "slither_findings", fake_slither)
    (project / "audit-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "protocol": "Bank",
                "chain": "ethereum",
                "entrypoints": ["src/Bank.sol"],
                "assets": ["ETH deposits"],
                "actors": ["depositor"],
                "trust_boundaries": ["Untrusted depositor can call withdraw"],
                "invariants": [
                    {
                        "id": "BALANCE",
                        "statement": "Withdrawals cannot exceed deposits",
                        "forge_test": "test/Bank.t.sol:BankTest::invariant_Balance()",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    async def fake_forge(root, timeout=300):
        return {
            "status": "completed",
            "tests": [
                {
                    "suite": "test/Bank.t.sol:BankTest",
                    "name": "invariant_Balance()",
                    "status": "Success",
                    "kind": "Invariant",
                }
            ],
        }

    monkeypatch.setattr(audit_engine, "run_forge_tests", fake_forge)
    report = await run_audit(project, FakeProvider(), forge_tests=True)
    assert report["status"] == "completed"
    assert report["checks"]["invariants"]["results"][0]["status"] == "test_passed"
    assert report["summary"]["by_origin"] == {"ai": 1, "slither": 1}
    assert len(report["findings"]) == 2


@pytest.mark.asyncio
async def test_slither_zero_contract_output_is_failure(project, monkeypatch):
    from vulnhunter import audit_engine

    async def empty_slither(*args, **kwargs):
        return ProcessResult(
            0,
            json.dumps({"success": True, "results": {"compilations": [], "detectors": []}}),
            "",
        )

    monkeypatch.setattr(audit_engine, "run_process", empty_slither)
    monkeypatch.setattr(
        audit_engine, "find_tool", lambda name: "dummy" if name == "slither" else None
    )
    check = await audit_engine.slither_findings(project, {"src/Bank.sol": SOURCE})
    assert check["status"] == "failed"
    assert check["compiled_files"] == []
    assert check["uncompiled_files"] == ["src/Bank.sol"]


def test_scope_rejects_parent_and_symlink_escape(project, tmp_path):
    (project / "scope.txt").write_text("../outside.sol\n", encoding="utf-8")
    with pytest.raises((ValueError, FileNotFoundError)):
        load_scope(project)
    (project / "scope.txt").write_text("src/Bank.sol\n", encoding="utf-8")
    assert list(load_scope(project)) == ["src/Bank.sol"]


def test_explicit_empty_scope_does_not_expand_to_project(project):
    (project / "scope.txt").write_text("# pending scope approval\n", encoding="utf-8")
    with pytest.raises(ValueError, match="No Solidity files"):
        load_scope(project)


def test_static_signal_is_a_clue_not_verification():
    findings = static_findings({"Bank.sol": SOURCE})
    assert any(item["title"] == "External call before accounting update" for item in findings)
    assert (
        static_findings({"Safe.sol": "contract X { // tx.origin\n function f() public {} }"}) == []
    )


@pytest.mark.asyncio
async def test_proof_rejects_changed_source_before_execution(project, tmp_path):
    report = await run_audit(project, FakeProvider(), slither=False)
    proof = tmp_path / "Proof.t.sol"
    proof.write_text("contract Proof { function testExploit() public {} }", encoding="utf-8")
    (project / "src/Bank.sol").write_text(SOURCE + "// changed", encoding="utf-8")
    with pytest.raises(ValueError, match="source changed"):
        await verify_poc(project, report, proof)


@pytest.mark.asyncio
async def test_proof_requires_a_real_passing_test(project, tmp_path, monkeypatch):
    from vulnhunter import poc_verifier

    report = await run_audit(project, FakeProvider(), slither=False)
    proof = tmp_path / "Proof.t.sol"
    proof.write_text("contract Proof { function testExploit() public {} }", encoding="utf-8")

    async def no_tests(*args, **kwargs):
        return ProcessResult(0, "{}", "")

    monkeypatch.setattr(poc_verifier, "run_process", no_tests)
    result = await verify_poc(project, report, proof, forge=sys.executable)
    assert result["status"] == "poc_test_failed"

    async def one_test(*args, **kwargs):
        return ProcessResult(0, '{"Proof":{"testExploit()":{"status":"Success"}}}', "")

    monkeypatch.setattr(poc_verifier, "run_process", one_test)
    result = await verify_poc(project, report, proof, forge=sys.executable)
    assert result["status"] == "poc_test_passed"
    assert result["passed_tests"] == 1


def test_proof_imports_are_limited_to_audited_snapshot():
    source = 'import "../src/Bank.sol"; contract Proof { function testCase() public {} }'
    validate_proof_source(source, ["src/Bank.sol"])
    with pytest.raises(ValueError, match="exact audited paths"):
        validate_proof_source(source.replace("../src/Bank.sol", "forge-std/Test.sol"), ["src/Bank.sol"])
    with pytest.raises(ValueError, match="network, filesystem"):
        validate_proof_source(source + " vm.createFork('https://example.com');", ["src/Bank.sol"])


@pytest.mark.asyncio
async def test_failed_proof_keeps_bounded_forge_diagnostic(project, tmp_path, monkeypatch):
    from vulnhunter import poc_verifier

    report = await run_audit(project, FakeProvider(), slither=False)
    proof = tmp_path / "Proof.t.sol"
    proof.write_text("contract Proof { function testExploit() public {} }", encoding="utf-8")

    async def failed_compile(*args, **kwargs):
        return ProcessResult(1, "", "compiler error: missing audited import")

    monkeypatch.setattr(poc_verifier, "run_process", failed_compile)
    result = await verify_poc(project, report, proof, forge=sys.executable)
    assert result["status"] == "poc_test_failed"
    assert result["diagnostic"] == "compiler error: missing audited import"


@pytest.mark.asyncio
async def test_legacy_orchestrator_import_and_static_mode(monkeypatch):
    from vulnhunter.config import settings

    monkeypatch.setattr(settings, "llm_provider", "static")
    result = await AutonomousOrchestrator().autonomous_audit(SOURCE)
    assert result.status == "partial"
    assert result.vulnerability_found
    assert not result.exploit_generated
