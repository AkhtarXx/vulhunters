"""Run Foundry project tests and retain compact, structured evidence."""

import asyncio
import hashlib
import json
import os
import tempfile
from pathlib import Path

from .process import find_tool, run_process

MAX_RESULTS_BYTES = 50_000_000


def summarize_forge_results(payload: object, exit_code: int) -> dict:
    if not isinstance(payload, dict):
        raise TypeError("Forge results are not a JSON object")
    tests = []
    for suite, details in sorted(payload.items()):
        if not isinstance(details, dict):
            continue
        results = details.get("test_results", {})
        if not isinstance(results, dict):
            continue
        for name, entry in sorted(results.items()):
            if not isinstance(entry, dict):
                continue
            kind_data = entry.get("kind", {})
            kind = next(iter(kind_data), "Unknown") if isinstance(kind_data, dict) else "Unknown"
            metrics = kind_data.get(kind, {}) if isinstance(kind_data, dict) else {}
            if not isinstance(metrics, dict):
                metrics = {}
            tests.append(
                {
                    "suite": suite,
                    "name": name,
                    "status": entry.get("status", "Unknown"),
                    "kind": kind,
                    "reason": str(entry.get("reason"))[:1000] if entry.get("reason") else None,
                    "counterexample": entry.get("counterexample") is not None,
                    "metrics": {
                        key: metrics[key]
                        for key in ("runs", "calls", "reverts", "workers", "gas")
                        if isinstance(metrics.get(key), (int, float))
                    },
                }
            )
    passed = sum(item["status"] == "Success" for item in tests)
    failed = sum(item["status"] != "Success" for item in tests)
    return {
        "status": "completed" if exit_code == 0 and tests and failed == 0 else "failed",
        "exit_code": exit_code,
        "passed": passed,
        "failed": failed,
        "total": len(tests),
        "tests": tests,
        "note": "Passing tests cover only the properties and run counts shown here.",
    }


async def run_forge_tests(root: Path, timeout: int = 300) -> dict:
    """Use an offline, FFI-disabled Foundry run in the existing project layout."""
    from .config import settings

    if not (root / "foundry.toml").is_file():
        return {"status": "unavailable", "reason": "No foundry.toml in project root"}
    binary = settings.foundry_path or find_tool("forge")
    if not binary:
        return {"status": "unavailable", "reason": "Forge is not installed"}
    config_hash = hashlib.sha256((root / "foundry.toml").read_bytes()).hexdigest()
    command = [binary, "test", "--offline"]
    if settings.solc_path:
        command += ["--use", settings.solc_path]
    with tempfile.TemporaryDirectory(prefix="vulnhunters-forge-") as directory:
        result_path = Path(directory) / "results.json"
        command += ["--json-file", str(result_path)]
        env = os.environ.copy()
        env.update(
            {
                "FOUNDRY_FFI": "false",
                "FOUNDRY_FS_PERMISSIONS": "[]",
                "FOUNDRY_ALLOW_FAILURE": "false",
            }
        )
        try:
            result = await run_process(
                command,
                cwd=root,
                timeout=timeout,
                env=env,
                output_limit=2_000_000,
            )
        except (OSError, RuntimeError, asyncio.TimeoutError) as exc:
            return {"status": "failed", "reason": f"Forge execution: {type(exc).__name__}"}
        if not result_path.is_file():
            return {
                "status": "failed",
                "exit_code": result.returncode,
                "reason": "Forge produced no structured test results",
            }
        if result_path.stat().st_size > MAX_RESULTS_BYTES:
            return {"status": "failed", "reason": "Forge results exceed size limit"}
        try:
            summary = summarize_forge_results(
                json.loads(result_path.read_text(encoding="utf-8")), result.returncode
            )
        except (UnicodeError, ValueError, TypeError) as exc:
            return {"status": "failed", "reason": f"Invalid Forge results: {exc}"}
    summary["foundry_config_sha256"] = config_hash
    summary["offline"] = True
    summary["ffi_enabled"] = False
    summary["compiler_override"] = settings.solc_path
    return summary
