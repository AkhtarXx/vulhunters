"""
Configuration management for VulnHunter.
Loads settings from environment variables and .env file.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Application configuration loaded from environment."""
    
    # Gemini API
    gemini_api_key: str = Field(..., description="Gemini API Key")
    gemini_model: str = Field(default="gemini-3-pro-preview", description="Default Gemini model for agents")
    gemini_pro_model: str = Field(default="gemini-3-pro-preview", description="Pro model for complex reasoning")
    deep_research_agent: str = Field(
        default="deep-research-pro-preview-12-2025",
        description="Deep Research Agent ID (only for research command)"
    )
    
    # MCP Server ports
    slither_mcp_port: int = Field(default=8001)
    
    # Application
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    debug: bool = Field(default=True)
    
    # Caching
    cache_ttl: int = Field(default=3600, description="Context cache TTL in seconds")
    file_search_store_prefix: str = Field(default="vuln_detector")
    
    # Blockchain (optional)
    eth_rpc_url: Optional[str] = Field(default=None, description="Ethereum RPC for fork testing")
    
    # Logging
    log_level: str = Field(default="INFO")
    
    # Rate Limiting (Gemini API)
    # Default limits based on Tier 1: 1M tokens/min, ~60 RPM
    rate_limit_tokens_per_min: int = Field(
        default=900_000,  # Stay under 1M limit
        env="RATE_LIMIT_TPM",
        description="Max tokens per minute (default: 900K, limit: 1M)"
    )
    rate_limit_requests_per_min: int = Field(
        default=50,  # Stay under 60 RPM
        env="RATE_LIMIT_RPM",
        description="Max requests per minute (default: 50, limit: 60)"
    )
    rate_limit_max_retries: int = Field(
        default=5,
        env="RATE_LIMIT_MAX_RETRIES",
        description="Max retries on 429 errors"
    )
    max_concurrent_contracts: int = Field(
        default=2,
        env="MAX_CONCURRENT_CONTRACTS",
        description="Max contracts to analyze in parallel"
    )
    
    # Analysis Configuration
    # Always enable resume mode for crash recovery
    always_resume: bool = Field(
        default=True, 
        env="VULNHUNTER_ALWAYS_RESUME",
        description="Always enable resume mode from checkpoints"
    )
    
    # Security Tools Configuration
    # Tool enable/disable flags
    slither_enabled: bool = Field(default=True, env="SLITHER_ENABLED")
    foundry_enabled: bool = Field(default=True, env="FOUNDRY_ENABLED")
    
    # Tool paths (optional - auto-detected if not specified)
    slither_path: Optional[str] = Field(default=None, env="SLITHER_PATH")
    foundry_path: Optional[str] = Field(default=None, env="FORGE_PATH")
    
    # Tool timeouts (seconds)
    slither_timeout: int = Field(default=60)
    foundry_timeout: int = Field(default=300)
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore"
    }


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Convenience access
settings = get_settings()
