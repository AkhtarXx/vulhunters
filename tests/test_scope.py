"""Explainable auto scope and explicit override behavior."""

import pytest

from vulnhunter.audit_engine import load_scope, run_audit
from vulnhunter.scope import plan_scope


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n')
    for directory in ("src", "shared", "test", "script", "mocks", "lib/vendor", "out"):
        (tmp_path / directory).mkdir(parents=True)
    (tmp_path / "src/Vault.sol").write_text(
        'pragma solidity ^0.8.20;\nimport "../shared/Math.sol";\ncontract Vault {}\n'
    )
    (tmp_path / "shared/Math.sol").write_text("pragma solidity ^0.8.20; library Math {}\n")
    (tmp_path / "test/Vault.t.sol").write_text("contract VaultTest {}\n")
    (tmp_path / "script/Deploy.s.sol").write_text("contract Deploy {}\n")
    (tmp_path / "mocks/MockToken.sol").write_text("contract MockToken {}\n")
    (tmp_path / "lib/vendor/External.sol").write_text("contract External {}\n")
    (tmp_path / "out/Generated.sol").write_text("contract Generated {}\n")
    return tmp_path


def included(plan):
    return {item["file"] for item in plan["included"]}


def test_auto_scope_selects_production_and_local_imports(repo):
    plan = plan_scope(repo)
    assert plan["mode"] == "auto"
    assert included(plan) == {"src/Vault.sol", "shared/Math.sol"}
    assert {item["file"] for item in plan["excluded"]} == {
        "test/Vault.t.sol",
        "script/Deploy.s.sol",
        "mocks/MockToken.sol",
    }
    assert any("lib" in item["path"] for item in plan["ignored_paths"])


def test_file_target_is_focused_and_follows_imports(repo):
    plan = plan_scope(repo / "src/Vault.sol")
    assert plan["root"] == repo
    assert plan["mode"] == "file"
    assert included(plan) == {"src/Vault.sol", "shared/Math.sol"}


def test_full_mode_overrides_scope_file_and_includes_tests_and_vendor(repo):
    (repo / "scope.txt").write_text("src/Vault.sol\n")
    default = plan_scope(repo)
    assert default["mode"] == "explicit"
    assert included(default) == {"src/Vault.sol"}
    full = plan_scope(repo, mode="full")
    assert included(full) == {
        "src/Vault.sol",
        "shared/Math.sol",
        "test/Vault.t.sol",
        "script/Deploy.s.sol",
        "mocks/MockToken.sol",
        "lib/vendor/External.sol",
    }
    assert "out/Generated.sol" not in included(full)
    auto = plan_scope(repo, mode="auto")
    assert included(auto) == {"src/Vault.sol", "shared/Math.sol"}


@pytest.mark.asyncio
async def test_audit_report_records_scope_decisions(repo):
    report = await run_audit(repo, None, slither=False)
    assert report["scope"]["mode"] == "auto"
    assert report["files"] == ["shared/Math.sol", "src/Vault.sol"]
    assert any(item["file"] == "test/Vault.t.sol" for item in report["scope"]["excluded"])


def test_full_scope_respects_configurable_cap(repo):
    with pytest.raises(ValueError, match="max-files"):
        load_scope(repo, mode="full", max_files=2)


def test_foundry_custom_source_root(tmp_path):
    (tmp_path / "foundry.toml").write_text(
        '[profile.default]\nsrc = "packages/core"\ntest = "checks"\n'
    )
    (tmp_path / "packages/core").mkdir(parents=True)
    (tmp_path / "checks").mkdir()
    (tmp_path / "packages/core/Main.sol").write_text("contract Main {}")
    (tmp_path / "checks/MainTest.sol").write_text("contract MainTest {}")
    plan = plan_scope(tmp_path)
    assert included(plan) == {"packages/core/Main.sol"}
    assert plan["excluded"][0]["reason"] == "test or deployment path from project config"


def test_hardhat_literal_custom_source_root(tmp_path):
    (tmp_path / "hardhat.config.ts").write_text(
        'export default { paths: { sources: "packages/contracts", tests: "checks" } };'
    )
    (tmp_path / "packages/contracts").mkdir(parents=True)
    (tmp_path / "checks").mkdir()
    (tmp_path / "packages/contracts/Main.sol").write_text("contract Main {}")
    (tmp_path / "checks/MainTest.sol").write_text("contract MainTest {}")
    assert included(plan_scope(tmp_path)) == {"packages/contracts/Main.sol"}


def test_full_override_does_not_require_valid_project_config(tmp_path):
    (tmp_path / "foundry.toml").write_text("not valid [ toml")
    (tmp_path / "Main.sol").write_text("contract Main {}")
    assert included(plan_scope(tmp_path, mode="full")) == {"Main.sol"}


def test_dynamic_hardhat_source_requires_review(tmp_path):
    (tmp_path / "hardhat.config.ts").write_text(
        "export default { paths: { sources: process.env.SOURCE_DIR } };"
    )
    (tmp_path / "alternate").mkdir()
    (tmp_path / "alternate/Main.sol").write_text("contract Main {}")
    with pytest.raises(ValueError, match="No production Solidity"):
        plan_scope(tmp_path)
    assert included(plan_scope(tmp_path, mode="full")) == {"alternate/Main.sol"}


def test_foundry_active_profile_source_path(tmp_path, monkeypatch):
    (tmp_path / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\n[profile.audit]\nsrc = "audit-src"\n'
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "audit-src").mkdir()
    (tmp_path / "src/Old.sol").write_text("contract Old {}")
    (tmp_path / "audit-src/New.sol").write_text("contract New {}")
    monkeypatch.setenv("FOUNDRY_PROFILE", "audit")
    assert included(plan_scope(tmp_path)) == {"audit-src/New.sol"}
