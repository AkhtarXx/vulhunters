"""Run an explicitly supplied Foundry proof in an isolated source snapshot."""

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from .audit_engine import load_scope
from .process import find_tool, run_process


def validate_proof_source(source: str, audited_files: list[str]) -> None:
    """Allow imports only from the exact source snapshot copied into Foundry."""
    allowed = {f"../{path.replace(chr(92), '/')}" for path in audited_files}
    for declaration in re.findall(r"\bimport\b([^;]*);", source, flags=re.DOTALL):
        paths = re.findall(r"[\"']([^\"']+)[\"']", declaration)
        if len(paths) != 1 or paths[0] not in allowed:
            raise ValueError(
                "Proof imports must use the exact audited paths relative to test/Proof.t.sol"
            )
    if re.search(
        r"\b(?:createFork|createSelectFork|selectFork|activeFork|rpc|ffi|readFile|writeFile|"
        r"readDir|writeJson|startBroadcast|broadcast)\s*\(",
        source,
    ):
        raise ValueError("Proof requests a network, filesystem, FFI, or broadcast operation")


async def verify_poc(
    project: Path,
    report: dict,
    proof: Path,
    *,
    timeout: int = 300,
    forge: str | None = None,
) -> dict:
    sources = load_scope(project, files=report.get("files"))
    if {
        p: hashlib.sha256(s.encode()).hexdigest() for p, s in sources.items()
    } != report.get("source_sha256"):
        raise ValueError("Project source changed since the audit; rerun audit first")
    proof = proof.resolve(strict=True)
    if proof.suffix.lower() != ".sol" or proof.stat().st_size > 500_000:
        raise ValueError("Proof must be a Solidity file smaller than 500 KB")
    proof_source = proof.read_text(encoding="utf-8")
    if not re.search(r"\bfunction\s+test\w*\s*\(", proof_source):
        raise ValueError("Proof must define at least one Foundry test function")
    validate_proof_source(proof_source, list(sources))
    from .config import settings

    binary = forge or settings.foundry_path or find_tool("forge")
    if not binary or not Path(binary).is_file():
        raise RuntimeError(
            "Forge is not installed; install Foundry and ensure forge is on PATH"
        )
    with tempfile.TemporaryDirectory(prefix="vulnhunters-proof-") as directory:
        root = Path(directory)
        for relative, source in sources.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
        test = root / "test" / "Proof.t.sol"
        test.parent.mkdir()
        test.write_text(proof_source, encoding="utf-8")
        compiler = settings.solc_path or find_tool("solc")
        compiler_config = f'solc = "{Path(compiler).resolve().as_posix()}"\n' if compiler else ""
        (root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "."\ntest = "test"\nffi = false\nfs_permissions = []\n'
            + compiler_config,
            encoding="utf-8",
        )
        env = {
            key: os.environ[key]
            for key in ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR")
            if key in os.environ
        }
        env.update(
            {
                "HOME": str(root),
                "USERPROFILE": str(root),
                "TEMP": str(root),
                "TMP": str(root),
                "FOUNDRY_HOME": str(root),
                "FOUNDRY_FFI": "false",
                "FOUNDRY_FS_PERMISSIONS": "[]",
            }
        )
        result = await run_process(
            [
                binary,
                "test",
                "--root",
                str(root),
                "--match-path",
                "test/Proof.t.sol",
                "--offline",
                "--json",
            ],
            cwd=root,
            timeout=timeout,
            env=env,
        )
    # Count only structured Foundry test entries. An empty successful run is not proof.
    try:
        output = json.loads(result.stdout)
    except ValueError:
        output = {}

    def count_passed(value: object) -> int:
        if not isinstance(value, dict):
            return 0
        return sum(
            (
                1
                if key.startswith("test")
                and isinstance(item, dict)
                and item.get("status") == "Success"
                else 0
            )
            + count_passed(item)
            for key, item in value.items()
        )

    passed = count_passed(output)
    outcome = {
        "status": "poc_test_passed"
        if result.returncode == 0 and passed > 0
        else "poc_test_failed",
        "passed_tests": passed,
        "exit_code": result.returncode,
        "proof_sha256": hashlib.sha256(proof_source.encode()).hexdigest(),
        "note": "Passing a test is not independent exploit verification; review assertions and value transfer.",
    }
    if outcome["status"] == "poc_test_failed":
        outcome["diagnostic"] = (result.stderr.strip() or result.stdout.strip())[-2000:]
    return outcome
