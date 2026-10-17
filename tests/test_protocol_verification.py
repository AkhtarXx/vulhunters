"""Protocol assumptions and structured Foundry evidence gates."""

import json

import pytest

from vulnhunter.forge_runner import summarize_forge_results
from vulnhunter.protocol_model import load_protocol_model


def manifest():
    return {
        "schema_version": 1,
        "protocol": "Vault",
        "chain": "ethereum",
        "entrypoints": ["src/Vault.sol"],
        "assets": ["ETH"],
        "actors": ["depositor", "admin"],
        "trust_boundaries": ["User is untrusted; admin can pause"],
        "invariants": [
            {
                "id": "SOLVENCY",
                "statement": "Liabilities never exceed assets",
                "forge_test": "test/Vault.t.sol:VaultTest::invariant_Solvency()",
            }
        ],
    }


def test_protocol_model_requires_in_scope_entrypoint_and_matching_chain(tmp_path):
    path = tmp_path / "audit-manifest.json"
    path.write_text(json.dumps(manifest()), encoding="utf-8")
    loaded = load_protocol_model(tmp_path, "ethereum", {"src/Vault.sol": "contract Vault {}"})
    assert loaded["status"] == "declared"
    assert loaded["model"]["invariants"][0]["id"] == "SOLVENCY"
    with pytest.raises(ValueError, match="chain"):
        load_protocol_model(tmp_path, "base", {"src/Vault.sol": "contract Vault {}"})
    with pytest.raises(ValueError, match="entrypoints"):
        load_protocol_model(tmp_path, "ethereum", {"src/Other.sol": "contract Other {}"})


def test_forge_summary_preserves_fuzz_and_invariant_run_counts():
    output = {
        "test/Vault.t.sol:VaultTest": {
            "test_results": {
                "testFuzz_Deposit(uint256)": {
                    "status": "Success",
                    "reason": None,
                    "kind": {"Fuzz": {"runs": 256, "gas": 1000}},
                },
                "invariant_Solvency()": {
                    "status": "Failure",
                    "reason": "assertion failed",
                    "counterexample": {"sequence": []},
                    "kind": {"Invariant": {"runs": 12, "calls": 144, "reverts": 0}},
                },
            }
        }
    }
    result = summarize_forge_results(output, exit_code=1)
    assert result["status"] == "failed"
    assert (result["passed"], result["failed"]) == (1, 1)
    invariant = next(item for item in result["tests"] if item["kind"] == "Invariant")
    assert invariant["metrics"] == {"runs": 12, "calls": 144, "reverts": 0}
    assert invariant["counterexample"] is True


def test_zero_foundry_tests_is_not_a_pass():
    assert summarize_forge_results({}, exit_code=0)["status"] == "failed"


@pytest.mark.asyncio
async def test_changed_manifest_invalidates_audit_snapshot(tmp_path):
    from vulnhunter.audit_engine import run_audit

    (tmp_path / "src").mkdir()
    (tmp_path / "src/Vault.sol").write_text("contract Vault {}", encoding="utf-8")
    path = tmp_path / "audit-manifest.json"
    path.write_text(json.dumps(manifest()), encoding="utf-8")

    class MutatingProvider:
        name = "fake"

        async def generate(self, prompt, schema):
            path.write_text(json.dumps({**manifest(), "assets": ["changed"]}), encoding="utf-8")
            return {"findings": []}

    report = await run_audit(tmp_path, MutatingProvider(), slither=False)
    assert report["status"] == "failed"
    assert "manifest changed" in report["error"].lower()
