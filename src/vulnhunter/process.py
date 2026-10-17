"""Bounded subprocess execution without shell interpolation."""

import asyncio
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str


def find_tool(name: str) -> str | None:
    """Find an installed tool on PATH, in this venv, or in the local tool cache."""
    executable = name + (".exe" if os.name == "nt" else "")
    locations = [Path(sys.executable).parent / executable]
    root = Path(__file__).resolve().parents[2] / ".tools"
    if name in {"forge", "anvil", "cast"}:
        locations.append(root / "foundry" / executable)
    if name == "solc":
        locations.append(root / "solc" / executable)
    for path in locations:
        if path.is_file():
            return str(path)
    return shutil.which(name)


def executable_command(name: str) -> list[str]:
    """Resolve native executables and known npm shims without invoking cmd.exe."""
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"{name} is not installed or is not on PATH")
    resolved = Path(path)
    if os.name == "nt" and resolved.suffix.lower() in {".cmd", ".bat", ".ps1"}:
        packages = {
            "codex": ("@openai", "codex", "bin", "codex.js"),
            "claude": ("@anthropic-ai", "claude-code", "bin", "claude.exe"),
        }
        if name not in packages:
            raise RuntimeError(f"Use a native executable for {name}, not a shell shim")
        entry = resolved.parent / "node_modules" / Path(*packages[name])
        if not entry.is_file():
            # Older Claude Code releases ship cli.js instead of the native executable.
            if name == "claude":
                entry = (
                    resolved.parent / "node_modules/@anthropic-ai/claude-code/cli.js"
                )
            if not entry.is_file():
                raise RuntimeError(
                    f"Cannot resolve {name} npm entry point; reinstall its official CLI"
                )
        if entry.suffix == ".js":
            return executable_command("node") + [str(entry)]
        return [str(entry)]
    return [str(resolved)]


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    if os.name == "nt":
        # The PID comes from our own child process, never from user input.
        await asyncio.to_thread(
            subprocess.run,
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            capture_output=True,
            timeout=10,
        )
    else:
        import signal

        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    await proc.wait()


async def run_process(
    command: list[str],
    *,
    cwd: Path,
    stdin: str = "",
    timeout: float = 300,
    env: dict[str, str] | None = None,
    output_limit: int = 10_000_000,
) -> ProcessResult:
    options = {"start_new_session": True} if os.name != "nt" else {}
    proc = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(cwd),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        **options,
    )

    async def read(stream: asyncio.StreamReader) -> bytes:
        chunks = []
        size = 0
        while chunk := await stream.read(65536):
            size += len(chunk)
            if size > output_limit:
                raise RuntimeError("Child process exceeded output limit")
            chunks.append(chunk)
        return b"".join(chunks)

    async def communicate() -> tuple[bytes, bytes]:
        async def write() -> None:
            try:
                proc.stdin.write(stdin.encode("utf-8"))
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                proc.stdin.close()

        tasks = [
            asyncio.create_task(read(proc.stdout)),
            asyncio.create_task(read(proc.stderr)),
            asyncio.create_task(write()),
        ]
        try:
            stdout, stderr, _ = await asyncio.gather(*tasks)
            await proc.wait()
            return stdout, stderr
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    try:
        stdout, stderr = await asyncio.wait_for(communicate(), timeout=timeout)
    except BaseException:
        await _terminate(proc)
        raise
    return ProcessResult(
        proc.returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )
