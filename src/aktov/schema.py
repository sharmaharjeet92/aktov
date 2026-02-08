"""Canonical trace schema for Aktov.

All framework-specific data is canonicalized into these models before
transmission to the cloud API.  In SAFE mode, raw tool arguments are
never included — only semantic flags travel over the wire.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SemanticFlags(BaseModel):
    """Client-side extracted semantic signals — no raw args required."""

    model_config = ConfigDict(populate_by_name=True)

    sql_statement_type: Optional[Literal[
        "SELECT", "INSERT", "UPDATE", "DELETE", "DDL", "OTHER"
    ]] = None
    http_method: Optional[Literal[
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
    ]] = None
    is_external: Optional[bool] = None
    sensitive_dir_match: Optional[bool] = None
    has_network_calls: Optional[bool] = None
    argument_size_bucket: Optional[Literal[
        "small", "medium", "large", "very_large"
    ]] = None
    path_traversal_detected: Optional[bool] = None


class ActionOutcome(BaseModel):
    """Result of a single tool invocation."""

    model_config = ConfigDict(populate_by_name=True)

    status: Literal["success", "failure", "error", "timeout"]
    error_class: Optional[Literal[
        "permission_denied",
        "not_found",
        "timeout",
        "rate_limited",
        "validation_error",
        "internal_error",
    ]] = None
    response_size_bucket: Optional[Literal[
        "small", "medium", "large", "very_large"
    ]] = None


class Action(BaseModel):
    """A single tool invocation within a trace."""

    model_config = ConfigDict(populate_by_name=True)

    sequence_index: int
    tool_name: str
    tool_category: Literal[
        "read", "write", "execute", "network", "credential", "pii", "delete"
    ]
    semantic_flags: SemanticFlags = Field(default_factory=SemanticFlags)
    arguments: Optional[dict[str, Any]] = None  # Only populated in DEBUG mode
    outcome: Optional[ActionOutcome] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    latency_ms: Optional[float] = None


class TeamContext(BaseModel):
    """Optional context for multi-agent team scenarios."""

    model_config = ConfigDict(populate_by_name=True)

    team_id: Optional[str] = None
    team_role: Optional[str] = None
    team_size: Optional[int] = None
    shared_resource_id: Optional[str] = None
    coordination_events: Optional[list[str]] = None


class TracePayload(BaseModel):
    """Top-level payload sent to the Aktov cloud API."""

    model_config = ConfigDict(populate_by_name=True)

    agent_id: str
    agent_type: str
    task_id: Optional[str] = None
    session_id: Optional[str] = Field(
        default_factory=lambda: str(uuid.uuid4())
    )
    declared_intent: Optional[str] = None
    mode: Literal["safe", "debug"] = "safe"
    actions: list[Action] = Field(default_factory=list)
    metadata: Optional[dict[str, Any]] = None
    team_context: Optional[TeamContext] = None
    agent_fingerprint: Optional[str] = None

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

    trace_id: Optional[str] = None
    status: Literal["sent", "dropped", "failed", "queued", "evaluated"] = "sent"
    rules_evaluated: int = 0
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    error_code: Optional[str] = None
