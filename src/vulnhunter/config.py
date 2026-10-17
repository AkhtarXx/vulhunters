"""Environment-backed settings for the maintained audit CLI."""

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Audit settings; credentials remain with the provider's installed CLI."""

    llm_provider: Literal[
        "codex", "claude", "hermes-codex", "hermes-claude", "static"
    ] = "codex"
    llm_model: str | None = None
    llm_timeout: int = Field(default=300, ge=1, le=7200)
    scope_mode: Literal["default", "auto", "full", "explicit"] = Field(
        default="default", validation_alias="VULNHUNTERS_SCOPE_MODE"
    )
    slither_path: str | None = None
    foundry_path: str | None = Field(
        default=None, validation_alias=AliasChoices("FORGE_PATH", "FOUNDRY_PATH")
    )
    solc_path: str | None = None

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
