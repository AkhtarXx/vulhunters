"""Subscription mode must not inherit API-token or gateway settings."""

import json

import pytest

from vulnhunter import providers
from vulnhunter.process import ProcessResult


@pytest.mark.asyncio
async def test_claude_status_uses_isolated_settings(monkeypatch):
    seen = []

    async def fake_run(command, **kwargs):
        seen.append(command)
        return ProcessResult(1, json.dumps({"loggedIn": False, "authMethod": "none"}), "")

    monkeypatch.setattr(providers, "executable_command", lambda name: [name])
    monkeypatch.setattr(providers, "run_process", fake_run)
    status = await providers.CLIProvider("claude").status()

    assert seen == [["claude", "--setting-sources", "", "auth", "status"]]
    assert status["subscription"] is False
    assert "OAuth" in status["error"]


@pytest.mark.asyncio
async def test_claude_generation_keeps_oauth_and_excludes_settings(monkeypatch):
    seen = []

    async def fake_status(self):
        return {"subscription": True}

    async def fake_run(command, **kwargs):
        seen.append((command, kwargs["env"]))
        return ProcessResult(
            0, json.dumps({"is_error": False, "structured_output": {"ok": True}}), ""
        )

    monkeypatch.setattr(providers.CLIProvider, "status", fake_status)
    monkeypatch.setattr(providers, "executable_command", lambda name: [name])
    monkeypatch.setattr(providers, "run_process", fake_run)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "billing-key")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://localhost:1234")

    result = await providers.CLIProvider("claude").generate(
        "Return ok", {"type": "object"}
    )

    command, env = seen[0]
    assert result == {"ok": True}
    assert command[1:4] == ["--print", "--setting-sources", ""]
    assert "--bare" not in command
    assert "ANTHROPIC_API_KEY" not in env
    assert "ANTHROPIC_BASE_URL" not in env
