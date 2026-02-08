"""Canonical trace schema for Aktov.

All framework-specific data is canonicalized into these models before
transmission to the cloud API.  In SAFE mode, raw tool arguments are
never included — only semantic flags travel over the wire.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SemanticFlags(BaseModel):
    """Client-side extracted semantic signals — no raw args required."""

    model_config = ConfigDict(populate_by_name=True)

    sql_statement_type: (
        Literal["SELECT", "INSERT", "UPDATE", "DELETE", "DDL", "OTHER"] | None
    ) = None
    http_method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] | None = None
    is_external: bool | None = None
    sensitive_dir_match: bool | None = None
    has_network_calls: bool | None = None
    argument_size_bucket: Literal["small", "medium", "large", "very_large"] | None = None
    path_traversal_detected: bool | None = None


class ActionOutcome(BaseModel):
    """Result of a single tool invocation."""

    model_config = ConfigDict(populate_by_name=True)

    status: Literal["success", "failure", "error", "timeout"]
    error_class: (
        Literal[
            "permission_denied", "not_found", "timeout",
            "rate_limited", "validation_error", "internal_error",
        ] | None
    ) = None
    response_size_bucket: Literal["small", "medium", "large", "very_large"] | None = None


class Action(BaseModel):
    """A single tool invocation within a trace."""

    model_config = ConfigDict(populate_by_name=True)

    sequence_index: int
    tool_name: str
    tool_category: Literal[
        "read", "write", "execute", "network", "credential", "pii", "delete"
    ]
    semantic_flags: SemanticFlags = Field(default_factory=SemanticFlags)
    arguments: dict[str, Any] | None = None  # Only populated in DEBUG mode
    outcome: ActionOutcome | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    latency_ms: float | None = None


class TeamContext(BaseModel):
    """Optional context for multi-agent team scenarios."""

    model_config = ConfigDict(populate_by_name=True)

    team_id: str | None = None
    team_role: str | None = None
    team_size: int | None = None
    shared_resource_id: str | None = None
    coordination_events: list[str] | None = None


class TracePayload(BaseModel):
    """Top-level payload sent to the Aktov cloud API."""

    model_config = ConfigDict(populate_by_name=True)

    agent_id: str
    agent_type: str
    task_id: str | None = None
    session_id: str | None = Field(
        default_factory=lambda: str(uuid.uuid4())
    )
    declared_intent: str | None = None
    mode: Literal["safe", "debug"] = "safe"
    actions: list[Action] = Field(default_factory=list)
    metadata: dict[str, Any] | None = None
    team_context: TeamContext | None = None
    agent_fingerprint: str | None = None

    @field_validator("actions")
    @classmethod
    def validate_safe_mode_no_raw_args(
        cls, actions: list[Action], info: Any
    ) -> list[Action]:
        """In SAFE mode, ensure no action carries raw arguments."""
        mode = info.data.get("mode", "safe")
        if mode == "safe":
            for action in actions:
                if action.arguments is not None:
                    raise ValueError(
                        f"SAFE mode violation: action at index "
                        f"{action.sequence_index} ({action.tool_name}) "
                        f"contains raw arguments. Strip arguments before "
                        f"building the payload or switch to DEBUG mode."
                    )
        return actions


class TraceResponse(BaseModel):
    """Response from the Aktov cloud API after trace submission."""

    model_config = ConfigDict(populate_by_name=True)

    trace_id: str | None = None
    status: Literal["sent", "dropped", "failed", "queued", "evaluated"] = "sent"
    rules_evaluated: int = 0
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    suppressed_alerts: list[dict[str, Any]] = Field(default_factory=list)
    error_code: str | None = None
