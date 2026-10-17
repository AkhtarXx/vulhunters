"""Cross-file context must use only the audited snapshot and disclose omissions."""

import pytest

from vulnhunter.dependency_graph import build_import_graph, related_context


def test_import_graph_ignores_comments_and_resolves_local_imports():
    sources = {
        "src/Vault.sol": (
            '// import "Ghost.sol";\n'
            'import {Ledger} from "./Ledger.sol";\n'
            'import "@vendor/Token.sol";\n'
            "contract Vault {}\n"
        ),
        "src/Ledger.sol": "contract Ledger {}\n",
    }
    graph = build_import_graph(sources)
    assert graph["imports"]["src/Vault.sol"] == ["src/Ledger.sol"]
    assert graph["imported_by"]["src/Ledger.sol"] == ["src/Vault.sol"]
    assert graph["external_or_out_of_scope"]["src/Vault.sol"] == ["@vendor/Token.sol"]


def test_related_context_records_budget_omissions():
    sources = {
        "src/Vault.sol": 'import "./Ledger.sol";\ncontract Vault {}',
        "src/Ledger.sol": "contract Ledger {}",
    }
    graph = build_import_graph(sources)
    context, details = related_context("src/Vault.sol", sources, graph, max_chars=10)
    assert context == ""
    assert details["omitted"] == ["src/Ledger.sol"]


@pytest.mark.asyncio
async def test_audit_supplies_related_source_and_accepts_its_citation(tmp_path):
    from vulnhunter.audit_engine import run_audit

    (tmp_path / "src").mkdir()
    (tmp_path / "src/Vault.sol").write_text(
        'import "./Ledger.sol";\ncontract Vault {}\n', encoding="utf-8"
    )
    (tmp_path / "src/Ledger.sol").write_text(
        "contract Ledger { function credit() public {} }\n", encoding="utf-8"
    )

    class Provider:
        name = "fake"

        async def generate(self, prompt, schema):
            if "\nFILE src/Vault.sol\n" not in prompt:
                return {"findings": []}
            assert "RELATED FILE src/Ledger.sol" in prompt
            return {
                "findings": [
                    {
                        "title": "Related contract issue",
                        "severity": "low",
                        "file": "src/Ledger.sol",
                        "line": 1,
                        "description": "Evidence in related file",
                        "impact": "Example impact",
                        "recommendation": "Review the ledger",
                    }
                ]
            }

    report = await run_audit(tmp_path, Provider(), slither=False)
    assert report["checks"]["ai"]["status"] == "completed"
    assert report["import_graph"]["imports"]["src/Vault.sol"] == ["src/Ledger.sol"]
    assert report["checks"]["ai"]["context"]["src/Vault.sol"]["included"] == ["src/Ledger.sol"]
    assert report["findings"][0]["file"] == "src/Ledger.sol"
