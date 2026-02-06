"""Application settings loaded from environment variables with CW_ prefix."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings

# Default rules directory: workspace_root/rules/phase0
_WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_RULES_DIR = str(_WORKSPACE_ROOT / "rules" / "phase0")


class Settings(BaseSettings):
    """ChainWatch Cloud configuration.

    All values can be overridden via environment variables prefixed with ``CW_``.
    For example, ``CW_DATABASE_URL`` sets ``database_url``.
    """

    # Database
    database_url: str = "postgresql+asyncpg://chainwatch:chainwatch_dev@localhost:5432/chainwatch"

    # Auth
    api_key_salt: str = "chainwatch-dev-salt-change-in-production"

    # Environment
    environment: Literal["dev", "staging", "production"] = "dev"
    log_level: str = "INFO"

    # Ingestion limits
    webhook_timeout_seconds: int = 10
    max_trace_actions: int = 500

    # Rules
    rules_dir: str = _DEFAULT_RULES_DIR

    model_config = {
        "env_prefix": "CW_",
        "case_sensitive": False,
    }


settings = Settings()
