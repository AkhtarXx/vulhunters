"""Official CLI subscription adapters and Hermes OAuth transports.

Credentials stay with the vendor CLI. Contract text is supplied on stdin. The
adapters run in an empty temporary directory and do not grant file-write tools.
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import Protocol

from .process import executable_command, run_process


class ProviderError(RuntimeError):
    pass


class Provider(Protocol):
    name: str

    async def generate(self, prompt: str, schema: dict) -> dict: ...


def subscription_environment(provider: str) -> dict[str, str]:
    env = os.environ.copy()
    # Explicit subscription providers must not silently switch to API billing.
    keys = (
        ["OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_BASE_URL"]
        if provider == "codex"
        else [
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_BASE_URL",
            "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_USE_VERTEX",
            "CLAUDE_CODE_USE_FOUNDRY",
        ]
    )
    for key in keys:
        env.pop(key, None)
    return env


class CLIProvider:
    def __init__(self, name: str, model: str | None = None, timeout: int = 300):
        if name not in {"codex", "claude"}:
            raise ValueError(f"Unsupported subscription provider: {name}")
        self.name, self.model, self.timeout = name, model, timeout

    async def status(self) -> dict:
        try:
            command = executable_command(self.name)
            # Claude user settings may inject ANTHROPIC_AUTH_TOKEN and a gateway.
            # Check the same isolated OAuth context used for generation.
            args = (
                ["login", "status"]
                if self.name == "codex"
                else ["--setting-sources", "", "auth", "status"]
            )
            with tempfile.TemporaryDirectory(prefix="vulhunters-auth-") as directory:
                result = await run_process(
                    command + args,
                    cwd=Path(directory),
                    timeout=20,
                    env=subscription_environment(self.name),
                )
            if self.name == "claude":
                payload = json.loads(result.stdout)
                method = str(payload.get("authMethod", ""))
                logged_in = bool(payload.get("loggedIn"))
                subscription = logged_in and method in {
                    "oauth_token",
                    "claude.ai",
                    "oauth",
                }
            else:
                logged_in = result.returncode == 0
                subscription = (
                    logged_in and "chatgpt" in (result.stdout + result.stderr).lower()
                )
            status = {
                "provider": self.name,
                "installed": True,
                "logged_in": logged_in,
                "subscription": subscription,
                "login_command": "codex login"
                if self.name == "codex"
                else 'claude --setting-sources "" auth login',
            }
            if self.name == "claude" and not subscription:
                status["error"] = (
                    "Claude subscription OAuth is unavailable in isolated mode. "
                    "Check ~/.claude/settings.json for gateway/token overrides, "
                    'then run claude --setting-sources "" auth login with your '
                    "Claude subscription."
                )
            return status
        except (RuntimeError, OSError, ValueError, asyncio.TimeoutError) as exc:
            return {
                "provider": self.name,
                "installed": bool(__import__("shutil").which(self.name)),
                "logged_in": False,
                "subscription": False,
                "error": str(exc),
            }

    async def generate(self, prompt: str, schema: dict) -> dict:
        status = await self.status()
        if not status["subscription"]:
            login_command = (
                "codex login"
                if self.name == "codex"
                else 'claude --setting-sources "" auth login'
            )
            raise ProviderError(
                f"{self.name} subscription login unavailable. Run "
                f"{login_command} "
                "with your subscription account, then vulhunters doctor."
            )
        if len(prompt.encode("utf-8")) > 1_500_000:
            raise ProviderError("Prompt exceeds 1.5 MB; reduce scope")
        with tempfile.TemporaryDirectory(prefix="vulhunters-llm-") as directory:
            root = Path(directory)
            command = executable_command(self.name)
            if self.name == "codex":
                schema_file, output_file = root / "schema.json", root / "response.json"
                schema_file.write_text(json.dumps(schema), encoding="utf-8")
                command += [
                    "exec",
                    "--ignore-user-config",
                    "--sandbox",
                    "read-only",
                    "--skip-git-repo-check",
                    "--ephemeral",
                    "--color",
                    "never",
                    "--output-schema",
                    str(schema_file),
                    "--output-last-message",
                    str(output_file),
                ]
                if self.model:
                    command += ["--model", self.model]
                command += ["-"]
            else:
                command += [
                    "--print",
                    # --bare explicitly disables OAuth/keychain credentials.
                    # Empty setting sources exclude user gateway/API-token overrides.
                    "--setting-sources",
                    "",
                    "--tools",
                    "",
                    "--no-session-persistence",
                    "--strict-mcp-config",
                    "--mcp-config",
                    '{"mcpServers":{}}',
                    "--output-format",
                    "json",
                    "--json-schema",
                    json.dumps(schema),
                ]
                if self.model:
                    command += ["--model", self.model]
            try:
                result = await run_process(
                    command,
                    cwd=root,
                    stdin=prompt,
                    timeout=self.timeout,
                    env=subscription_environment(self.name),
                )
            except asyncio.TimeoutError as exc:
                raise ProviderError(
                    f"{self.name} timed out after {self.timeout}s"
                ) from exc
            if result.returncode:
                # Do not echo provider stderr: it may contain account details or credentials.
                raise ProviderError(
                    f"{self.name} failed (exit {result.returncode}); check login and quota"
                )
            try:
                if self.name == "codex":
                    return json.loads(output_file.read_text(encoding="utf-8"))
                envelope = json.loads(result.stdout)
                if envelope.get("is_error"):
                    raise ProviderError(
                        "Claude returned an error; check subscription quota"
                    )
                content = envelope.get("structured_output")
                if content is None:
                    content = json.loads(envelope.get("result", ""))
                if not isinstance(content, dict):
                    raise TypeError("Expected a JSON object")
                return content
            except (OSError, TypeError, ValueError) as exc:
                raise ProviderError(
                    f"{self.name} returned invalid structured output"
                ) from exc


class HermesProvider:
    """Use Hermes's actual direct SDK/OAuth transports, without its agent loop."""

    def __init__(self, name: str, model: str | None, timeout: int = 300):
        if name not in {"hermes-codex", "hermes-claude"}:
            raise ValueError(f"Unsupported Hermes provider: {name}")
        self.name, self.model, self.timeout = name, model, timeout
        self.vendor = "openai-codex" if name == "hermes-codex" else "anthropic"

    def installation(self) -> tuple[Path, Path]:
        roots = (
            [Path(os.environ["HERMES_SOURCE"])]
            if os.environ.get("HERMES_SOURCE")
            else []
        )
        roots += [
            Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
            / "hermes/hermes-agent",
            Path.home() / ".hermes/hermes-agent",
            Path.home() / "hermes-agent",
        ]
        for root in roots:
            if not (root / "hermes_cli/auth.py").is_file():
                continue
            interpreters = (
                [Path(os.environ["HERMES_PYTHON"])]
                if os.environ.get("HERMES_PYTHON")
                else []
            )
            interpreters += [
                root / "venv/Scripts/python.exe",
                root / ".venv/Scripts/python.exe",
                root / "venv/bin/python",
                root / ".venv/bin/python",
            ]
            for interpreter in interpreters:
                if interpreter.is_file():
                    return root.resolve(), interpreter.resolve()
        raise ProviderError(
            "Hermes runtime not found. Set HERMES_SOURCE and HERMES_PYTHON to your installed Hermes source and Python."
        )

    async def _request(self, **payload) -> dict:
        root, interpreter = self.installation()
        worker = Path(__file__).with_name("hermes_worker.py")
        request = {
            "root": str(root),
            "provider": self.vendor,
            "model": self.model,
            "timeout": self.timeout,
            **payload,
        }
        env = subscription_environment(
            "codex" if self.vendor == "openai-codex" else "claude"
        )
        with tempfile.TemporaryDirectory(prefix="vulhunters-hermes-") as directory:
            result = await run_process(
                [str(interpreter), str(worker)],
                cwd=Path(directory),
                stdin=json.dumps(request),
                env=env,
                timeout=self.timeout,
            )
        if result.returncode:
            raise ProviderError(
                "Hermes OAuth request failed. Run hermes auth status; check login, model access and quota."
            )
        try:
            return json.loads(result.stdout)
        except ValueError as exc:
            raise ProviderError("Hermes returned invalid JSON") from exc

    async def status(self) -> dict:
        try:
            await self._request(status_only=True)
            return {
                "provider": self.name,
                "installed": True,
                "logged_in": True,
                "subscription": True,
                "transport": "Hermes direct SDK/OAuth",
                "billing": "Claude Max extra usage credits"
                if self.vendor == "anthropic"
                else "ChatGPT OAuth; provider plan limits apply",
            }
        except (RuntimeError, OSError, asyncio.TimeoutError) as exc:
            try:
                self.installation()
                installed = True
            except ProviderError:
                installed = False
            return {
                "provider": self.name,
                "installed": installed,
                "logged_in": False,
                "subscription": False,
                "error": str(exc),
            }

    async def generate(self, prompt: str, schema: dict) -> dict:
        if not self.model:
            raise ProviderError(
                "Hermes direct providers require --model; choose a model enabled for your subscription"
            )
        return await self._request(prompt=prompt, schema=schema)


def get_provider(name: str, model: str | None = None, timeout: int = 300) -> Provider:
    if name in {"codex", "claude"}:
        return CLIProvider(name, model=model, timeout=timeout)
    if name in {"hermes-codex", "hermes-claude"}:
        return HermesProvider(name, model, timeout)
    raise ValueError(f"Unknown AI provider: {name}")
