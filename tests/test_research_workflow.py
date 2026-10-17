"""Research stages must preserve source evidence and unverified status."""

import re

import pytest

from vulnhunter.audit_engine import run_audit
from vulnhunter.dependency_graph import build_import_graph
from vulnhunter.providers import ProviderError
from vulnhunter.research_workflow import (
    _candidate_poc,
    _validate_hypotheses,
    run_research,
)

SOURCE = """pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw() external {
        (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""


class ResearchProvider:
    name = "fake"

    async def generate(self, prompt, schema):
        properties = schema["properties"]
        if "findings" in properties:
            return {"findings": []}
        if "hypotheses" in properties:
            assert "MAIN FILE src/Vault.sol" in prompt
            return {
                "hypotheses": [
                    {
                        "title": "Possible reentrancy",
                        "file": "src/Vault.sol",
                        "line": 5,
                        "actor": "Depositor with a callback",
                        "preconditions": "Depositor has a positive balance",
                        "attack_sequence": "Withdraw and reenter before reset",
                        "impact": "May withdraw more than balance",
                        "violated_property": "Assets cover liabilities",
                        "test_objective": "A local callback test should show excess withdrawal",
                    }
                ]
            }
        if "reviews" in properties:
            identifier = re.search(r"RH-[0-9a-f]{12}", prompt).group()
            return {
                "reviews": [
                    {
                        "hypothesis_id": identifier,
                        "assessment": "needs_test",
                        "counter_evidence": "The send may revert after balance exhaustion",
                        "missing_evidence": "No callback execution trace is provided",
                        "defensive_control": "Update balance before the external call",
                    }
                ]
            }
        raise AssertionError("Unexpected schema")


@pytest.mark.asyncio
async def test_red_and_blue_passes_do_not_confirm_a_finding(tmp_path):
    sources = {"src/Vault.sol": SOURCE}
    result = await run_research(
        tmp_path,
        {"files": list(sources)},
        sources,
        build_import_graph(sources),
        {"model": {"entrypoints": ["src/Vault.sol"]}},
        ResearchProvider(),
    )
    assert result["status"] == "completed"
    item = result["hypotheses"][0]
    assert item["source_evidence"].startswith("(bool ok,")
    assert item["state"] == "unverified_hypothesis"
    assert item["blue_review"]["assessment"] == "needs_test"
    assert "candidate_poc" not in item


def test_hypothesis_outside_supplied_lines_is_rejected():
    payload = {
        "hypotheses": [
            {
                "title": "Claim",
                "file": "Other.sol",
                "line": 999,
                "actor": "Anyone",
                "preconditions": "None",
                "attack_sequence": "Call",
                "impact": "Loss",
                "violated_property": "Safety",
                "test_objective": "Test it",
            }
        ]
    }
    with pytest.raises(ProviderError, match="outside supplied source"):
        _validate_hypotheses(payload, {"src/Vault.sol": SOURCE})


@pytest.mark.asyncio
async def test_audit_report_keeps_research_separate_from_findings(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/Vault.sol").write_text(SOURCE, encoding="utf-8")
    report = await run_audit(tmp_path, ResearchProvider(), slither=False, research=True)
    assert report["checks"]["research"]["status"] == "completed"
    assert len(report["research"]["hypotheses"]) == 1
    assert report["findings"] == []
    assert report["summary"]["verified_exploits"] == 0


@pytest.mark.asyncio
async def test_generated_poc_receives_exact_snapshot_imports(tmp_path, monkeypatch):
    from vulnhunter import poc_verifier

    class ProofProvider:
        async def generate(self, prompt, schema):
            assert 'import "../src/Vault.sol";' in prompt
            assert "forge-std and other external packages are unavailable" in prompt
            return {"test_source": "contract Proof { function testAttempt() public {} }"}

    async def fake_verify(project, report, proof, *, timeout):
        assert proof.read_text(encoding="utf-8").startswith("contract Proof")
        return {"status": "poc_test_failed", "diagnostic": "assertion failed"}

    monkeypatch.setattr(poc_verifier, "verify_poc", fake_verify)
    result = await _candidate_poc(
        tmp_path,
        {"files": ["src/Vault.sol"]},
        ProofProvider(),
        {"title": "Possible reentrancy"},
        SOURCE,
        timeout=5,
    )
    assert result["status"] == "poc_test_failed"
    assert result["diagnostic"] == "assertion failed"
    assert len(result["attempts"]) == 2


@pytest.mark.asyncio
async def test_generated_poc_uses_one_diagnostic_correction(tmp_path, monkeypatch):
    from vulnhunter import poc_verifier

    class CorrectionProvider:
        def __init__(self):
            self.calls = 0

        async def generate(self, prompt, schema):
            self.calls += 1
            if self.calls == 1:
                assert "PREVIOUS CANDIDATE" not in prompt
                return {"test_source": "contract Proof { function testFirst() public {} }"}
            assert "PREVIOUS CANDIDATE" in prompt
            assert "compile error" in prompt
            return {"test_source": "contract Proof { function testCorrected() public {} }"}

    async def fake_verify(project, report, proof, *, timeout):
        if "testFirst" in proof.read_text(encoding="utf-8"):
            return {"status": "poc_test_failed", "diagnostic": "compile error"}
        return {"status": "poc_test_passed", "passed_tests": 1, "exit_code": 0}

    monkeypatch.setattr(poc_verifier, "verify_poc", fake_verify)
    provider = CorrectionProvider()
    result = await _candidate_poc(
        tmp_path,
        {"files": ["src/Vault.sol"]},
        provider,
        {"title": "Possible reentrancy"},
        SOURCE,
        timeout=5,
    )
    assert provider.calls == 2
    assert result["status"] == "poc_test_passed"
    assert result["test_source"].endswith("testCorrected() public {} }")
    assert [item["status"] for item in result["attempts"]] == [
        "poc_test_failed",
        "poc_test_passed",
    ]
