"""Application settings loaded from environment variables with AK_ prefix."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings

# Default rules directory: workspace_root/rules/phase0
_WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_RULES_DIR = str(_WORKSPACE_ROOT / "rules" / "phase0")


class Settings(BaseSettings):
    """Aktov Cloud configuration.

    All values can be overridden via environment variables prefixed with ``AK_``.
    For example, ``AK_DATABASE_URL`` sets ``database_url``.
    """

    # Database
    database_url: str = "postgresql+asyncpg://aktov:aktov_dev@localhost:5432/aktov"

    # Auth
    api_key_salt: str = "aktov-dev-salt-change-in-production"

    # Environment
    environment: Literal["dev", "staging", "production"] = "dev"
    log_level: str = "INFO"

    # Ingestion limits
    webhook_timeout_seconds: int = 10
    max_trace_actions: int = 200
    max_payload_bytes: int = 262144  # 256KB
    max_tool_name_length: int = 256
    max_metadata_bytes: int = 10240  # 10KB

    # Rules
    rules_dir: str = _DEFAULT_RULES_DIR

    model_config = {
        "env_prefix": "AK_",
        "case_sensitive": False,
    }


settings = Settings()
