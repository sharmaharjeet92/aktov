"""Rule YAML validation and schema reference.

Provides:
- Schema registry of all valid fields, operators, and match types
- ``validate_rule()`` function for pre-load validation with typo suggestions
- Formatting helpers for CLI output (schema reference, examples, validation results)
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Schema registry — derived from aktov.schema Pydantic models
# ---------------------------------------------------------------------------

VALID_SEVERITIES = ("critical", "high", "medium", "low")

VALID_OPERATORS = {
    "equals": {
        "description": "Exact match",
        "example": 'equals: "read"',
    },
    "in": {
        "description": "Value is one of the listed values",
        "example": 'in: ["read", "write"]',
    },
    "not_in": {
        "description": "Value is NOT one of the listed values",
        "example": 'not_in: ["credential"]',
    },
    "contains_any": {
        "description": "Value (str or list) contains at least one listed item",
        "example": 'contains_any: ["network", "credential"]',
    },
    "greater_than": {
        "description": "Numeric greater than",
        "example": "greater_than: 50",
    },
    "less_than": {
        "description": "Numeric less than",
        "example": "less_than: 10",
    },
}

VALID_MATCH_TYPES = {
    "conditions": "Field-level checks (AND logic). All conditions must match.",
    "sequence": "Ordered action patterns. Step N must occur before Step N+1.",
    "consecutive": "N consecutive actions matching a condition.",
    "count": "At least N actions matching sub-conditions (non-consecutive).",
}

# Trace-level fields (no prefix needed)
TRACE_LEVEL_FIELDS: dict[str, dict[str, Any]] = {
    "action_count": {
        "type": "int",
        "description": "Number of actions in trace",
    },
    "agent_type": {
        "type": "str",
        "description": "Agent type (e.g., 'langchain', 'mcp', 'claude-code')",
    },
}

# Action-level fields (use with actions[*]. or actions[0]. prefix, or bare for legacy)
ACTION_FIELDS: dict[str, dict[str, Any]] = {
    "tool_name": {
        "type": "str",
        "description": "Name of the tool invoked",
    },
    "tool_category": {
        "type": "Literal",
        "values": ["read", "write", "execute", "network", "credential", "pii", "delete"],
        "description": "Canonical tool category",
    },
    "sequence_index": {
        "type": "int",
        "description": "0-based position in action sequence",
    },
    "latency_ms": {
        "type": "float",
        "description": "Tool call latency in milliseconds",
    },
    "outcome.status": {
        "type": "Literal",
        "values": ["success", "failure", "error", "timeout"],
        "description": "Tool call result status",
    },
    "outcome.error_class": {
        "type": "Literal",
        "values": [
            "permission_denied", "not_found", "timeout",
            "rate_limited", "validation_error", "internal_error",
        ],
        "description": "Error classification (when status is error/failure)",
    },
    "outcome.response_size_bucket": {
        "type": "Literal",
        "values": ["small", "medium", "large", "very_large"],
        "description": "Response payload size bucket",
    },
    "semantic_flags.sql_statement_type": {
        "type": "Literal",
        "values": ["SELECT", "INSERT", "UPDATE", "DELETE", "DDL", "OTHER"],
        "description": "Detected SQL statement type",
    },
    "semantic_flags.http_method": {
        "type": "Literal",
        "values": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        "description": "Detected HTTP method",
    },
    "semantic_flags.is_external": {
        "type": "bool",
        "description": "True if URL target is external (not localhost/private)",
    },
    "semantic_flags.sensitive_dir_match": {
        "type": "bool",
        "description": "True if path touches /etc, .ssh, .env, .aws, etc.",
    },
    "semantic_flags.has_network_calls": {
        "type": "bool",
        "description": "True if arguments contain http/https/ftp/ws URLs",
    },
    "semantic_flags.path_traversal_detected": {
        "type": "bool",
        "description": "True if arguments contain ../ patterns",
    },
    "semantic_flags.argument_size_bucket": {
        "type": "Literal",
        "values": ["small", "medium", "large", "very_large"],
        "description": "Argument payload size bucket",
    },
}

# Semantic flag names (for sequence step validation)
SEMANTIC_FLAG_NAMES = {
    k.removeprefix("semantic_flags.") for k in ACTION_FIELDS if k.startswith("semantic_flags.")
}

# All known field paths for fuzzy matching
ALL_KNOWN_FIELDS: set[str] = set()
ALL_KNOWN_FIELDS.update(TRACE_LEVEL_FIELDS.keys())
ALL_KNOWN_FIELDS.update(ACTION_FIELDS.keys())
# Also add prefixed versions
for f in list(ACTION_FIELDS.keys()):
    ALL_KNOWN_FIELDS.add(f"actions[*].{f}")
    ALL_KNOWN_FIELDS.add(f"actions[0].{f}")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

@dataclass
class ValidationError:
    """A single validation issue found in a rule definition."""

    path: str
    message: str
    suggestion: str = ""
    severity: str = "error"  # "error" or "warning"


def validate_rule(data: dict[str, Any]) -> list[ValidationError]:
    """Validate a rule definition dict.

    Returns a list of :class:`ValidationError` objects. An empty list means
    the rule is valid.
    """
    errors: list[ValidationError] = []

    # 1. Required top-level fields
    rule_id = data.get("rule_id") or data.get("id")
    if not rule_id:
        errors.append(ValidationError(
            path="rule_id",
            message="Missing required field 'rule_id' (or 'id')",
        ))

    name = data.get("name")
    if not name:
        errors.append(ValidationError(
            path="name",
            message="Missing required field 'name'",
        ))

    # 2. Severity
    severity = data.get("severity")
    if severity is not None and severity not in VALID_SEVERITIES:
        errors.append(ValidationError(
            path="severity",
            message=f"Unknown severity '{severity}'",
            suggestion=f"Expected one of: {', '.join(VALID_SEVERITIES)}",
            severity="warning",
        ))

    # 3. Match block
    match_block = data.get("match")
    if match_block is None:
        errors.append(ValidationError(
            path="match",
            message="Missing required 'match' block",
        ))
        return errors

    if not isinstance(match_block, dict):
        errors.append(ValidationError(
            path="match",
            message="'match' must be a mapping",
        ))
        return errors

    # 4. Match type
    found_types = [t for t in VALID_MATCH_TYPES if t in match_block]
    if not found_types:
        errors.append(ValidationError(
            path="match",
            message="No match type found",
            suggestion=f"Use one of: {', '.join(VALID_MATCH_TYPES.keys())}",
        ))
        return errors

    match_type = found_types[0]

    # Dispatch to type-specific validation
    if match_type == "conditions":
        errors.extend(_validate_conditions(match_block["conditions"], "match.conditions"))
    elif match_type == "sequence":
        errors.extend(_validate_sequence(match_block["sequence"], "match.sequence"))
    elif match_type == "consecutive":
        errors.extend(_validate_consecutive(match_block["consecutive"], "match.consecutive"))
    elif match_type == "count":
        errors.extend(_validate_count(match_block["count"], "match.count"))

    return errors


def _validate_conditions(
    conditions: Any, path_prefix: str
) -> list[ValidationError]:
    """Validate a conditions list."""
    errors: list[ValidationError] = []

    if not isinstance(conditions, list):
        errors.append(ValidationError(
            path=path_prefix,
            message="'conditions' must be a list",
        ))
        return errors

    for i, cond in enumerate(conditions):
        cpath = f"{path_prefix}[{i}]"

        if not isinstance(cond, dict):
            errors.append(ValidationError(path=cpath, message="Condition must be a mapping"))
            continue

        # Field path
        field_path = cond.get("field")
        if not field_path:
            errors.append(ValidationError(path=f"{cpath}.field", message="Missing 'field' key"))
            continue

        errors.extend(_validate_field_path(field_path, f"{cpath}.field"))

        # Operator
        errors.extend(_validate_has_operator(cond, cpath))

    return errors


def _validate_sequence(
    steps: Any, path_prefix: str
) -> list[ValidationError]:
    """Validate a sequence steps list."""
    errors: list[ValidationError] = []

    if not isinstance(steps, list):
        errors.append(ValidationError(
            path=path_prefix,
            message="'sequence' must be a list of steps",
        ))
        return errors

    for i, step in enumerate(steps):
        spath = f"{path_prefix}[{i}]"

        if not isinstance(step, dict):
            errors.append(ValidationError(path=spath, message="Step must be a mapping"))
            continue

        condition = step.get("condition")
        if not condition or not isinstance(condition, dict):
            errors.append(ValidationError(
                path=f"{spath}.condition",
                message="Each step must have a 'condition' mapping with 'field' and 'equals'",
            ))
            continue

        field_path = condition.get("field")
        if not field_path:
            errors.append(ValidationError(
                path=f"{spath}.condition.field",
                message="Missing 'field' in step condition",
            ))
        else:
            # Sequence conditions operate at action level directly
            errors.extend(_validate_field_path(field_path, f"{spath}.condition.field"))

        if "equals" not in condition:
            errors.append(ValidationError(
                path=f"{spath}.condition",
                message="Step condition must use 'equals' operator",
            ))

        # Semantic flags
        sem_flags = step.get("semantic_flags")
        if sem_flags and isinstance(sem_flags, dict):
            for flag_name in sem_flags:
                if flag_name not in SEMANTIC_FLAG_NAMES:
                    suggestion = ""
                    matches = difflib.get_close_matches(
                        flag_name, SEMANTIC_FLAG_NAMES, n=1, cutoff=0.6
                    )
                    if matches:
                        suggestion = f"Did you mean '{matches[0]}'?"
                    errors.append(ValidationError(
                        path=f"{spath}.semantic_flags.{flag_name}",
                        message=f"Unknown semantic flag '{flag_name}'",
                        suggestion=suggestion,
                    ))

    return errors


def _validate_consecutive(
    consec_block: Any, path_prefix: str
) -> list[ValidationError]:
    """Validate a consecutive match block."""
    errors: list[ValidationError] = []

    if not isinstance(consec_block, dict):
        errors.append(ValidationError(
            path=path_prefix,
            message="'consecutive' must be a mapping",
        ))
        return errors

    if "field" not in consec_block:
        errors.append(ValidationError(
            path=f"{path_prefix}.field",
            message="Missing required 'field' key",
        ))
    else:
        errors.extend(_validate_field_path(
            consec_block["field"], f"{path_prefix}.field"
        ))

    if "in" not in consec_block:
        errors.append(ValidationError(
            path=f"{path_prefix}.in",
            message="Missing required 'in' list of allowed values",
        ))
    elif not isinstance(consec_block["in"], list):
        errors.append(ValidationError(
            path=f"{path_prefix}.in",
            message="'in' must be a list",
        ))

    if "min_count" not in consec_block:
        errors.append(ValidationError(
            path=f"{path_prefix}.min_count",
            message="Missing required 'min_count' (integer >= 1)",
        ))

    return errors


def _validate_count(
    count_block: Any, path_prefix: str
) -> list[ValidationError]:
    """Validate a count match block."""
    errors: list[ValidationError] = []

    if not isinstance(count_block, dict):
        errors.append(ValidationError(
            path=path_prefix,
            message="'count' must be a mapping",
        ))
        return errors

    if "conditions" not in count_block:
        errors.append(ValidationError(
            path=f"{path_prefix}.conditions",
            message="Missing required 'conditions' list",
        ))
    else:
        errors.extend(_validate_conditions(
            count_block["conditions"], f"{path_prefix}.conditions"
        ))

    if "min_count" not in count_block and "min_distinct" not in count_block:
        errors.append(ValidationError(
            path=path_prefix,
            message="Must specify at least 'min_count' or 'min_distinct'",
        ))

    return errors


# ---------------------------------------------------------------------------
# Field path + operator validation helpers
# ---------------------------------------------------------------------------

def _validate_field_path(
    field_path: str, error_path: str
) -> list[ValidationError]:
    """Check that a field path is a known field. Returns errors if unknown."""
    # Normalize: strip actions[*]. or actions[0]. prefix for lookup
    bare_path = field_path
    if field_path.startswith("actions[*]."):
        bare_path = field_path[len("actions[*]."):]
    elif field_path.startswith("actions[0]."):
        bare_path = field_path[len("actions[0]."):]

    # Check if it's a known trace-level or action-level field
    if bare_path in TRACE_LEVEL_FIELDS or bare_path in ACTION_FIELDS:
        return []

    # Unknown — try fuzzy match
    all_bare = set(TRACE_LEVEL_FIELDS.keys()) | set(ACTION_FIELDS.keys())
    matches = difflib.get_close_matches(bare_path, all_bare, n=1, cutoff=0.6)
    suggestion = f"Did you mean '{matches[0]}'?" if matches else ""

    return [ValidationError(
        path=error_path,
        message=f"Unknown field '{field_path}'",
        suggestion=suggestion,
    )]


def _validate_has_operator(
    cond: dict[str, Any], error_path: str
) -> list[ValidationError]:
    """Check that a condition has at least one operator."""
    has_modern = any(op in cond for op in VALID_OPERATORS)
    has_legacy = "operator" in cond

    if not has_modern and not has_legacy:
        return [ValidationError(
            path=error_path,
            message="No operator found in condition",
            suggestion=f"Use one of: {', '.join(VALID_OPERATORS.keys())}",
        )]

    return []


# ---------------------------------------------------------------------------
# Formatting for CLI output
# ---------------------------------------------------------------------------

def format_schema_output(section: str | None = None) -> str:
    """Return formatted schema reference for CLI output.

    *section*: ``"fields"``, ``"operators"``, ``"match-types"``, or ``None`` (all).
    """
    parts: list[str] = []

    if section is None:
        parts.append("")
        parts.append("  Aktov Rule Schema Reference")
        parts.append("  ============================")

    if section in (None, "fields"):
        parts.append("")
        parts.append("  FIELDS (trace-level)")
        parts.append("")
        for name, info in TRACE_LEVEL_FIELDS.items():
            desc = info.get("description", "")
            ftype = info["type"]
            parts.append(f"    {name:<20s} {ftype:<10s} {desc}")

        parts.append("")
        parts.append("  FIELDS (action-level — prefix with actions[*]. or actions[0].)")
        parts.append("")
        for name, info in ACTION_FIELDS.items():
            ftype = info["type"]
            desc = info.get("description", "")
            values = info.get("values")
            if values:
                vals_str = " | ".join(str(v) for v in values)
                parts.append(f"    {name:<42s} {ftype:<10s} {vals_str}")
            else:
                parts.append(f"    {name:<42s} {ftype:<10s} {desc}")

    if section in (None, "operators"):
        parts.append("")
        parts.append("  OPERATORS")
        parts.append("")
        for name, info in VALID_OPERATORS.items():
            desc = info["description"]
            example = info["example"]
            parts.append(f"    {name:<14s} {desc:<46s} {example}")

    if section in (None, "match-types"):
        parts.append("")
        parts.append("  MATCH TYPES")
        parts.append("")
        for name, desc in VALID_MATCH_TYPES.items():
            parts.append(f"    {name:<14s} {desc}")

    if section is None:
        parts.append("")
        parts.append("  For full examples: aktov rules examples")

    parts.append("")
    return "\n".join(parts)


def format_examples_output() -> str:
    """Return rule-writing guide with one example per match type."""
    return """
  Aktov Rule-Writing Guide
  =========================

  Each rule is a YAML file with: rule_id, name, severity, match block.
  Drop YAML files into a directory and load with: rules_dir="./my-rules"

  --- conditions (field-level checks, AND logic) ---

  rule_id: MY-001
  name: credential_access_from_wrong_agent
  severity: critical
  match:
    conditions:
      - field: agent_type                       # trace-level field
        not_in: ["credential_manager", "vault"]
      - field: actions[*].tool_category         # any action matches
        contains_any: ["credential"]

  --- sequence (ordered action patterns) ---

  rule_id: MY-002
  name: read_then_exfiltrate
  severity: critical
  match:
    sequence:
      - step: read_phase
        condition:
          field: tool_category
          equals: "read"
      - step: egress_phase
        condition:
          field: tool_category
          equals: "network"
        semantic_flags:
          is_external: true

  --- consecutive (N in a row) ---

  rule_id: MY-003
  name: burst_failures
  severity: medium
  match:
    consecutive:
      field: actions[*].outcome.status
      in: ["failure", "error"]
      min_count: 3

  --- count (at least N matching, non-consecutive) ---

  rule_id: MY-004
  name: many_credential_accesses
  severity: high
  match:
    count:
      conditions:
        - field: tool_category
          equals: "credential"
      min_count: 3

  Field paths:
    actions[*].X   — any action (wildcard)
    actions[0].X   — first action only
    agent_type     — trace-level
    action_count   — trace-level

  Full schema reference: aktov rules schema
  Validate before loading: aktov rules validate my-rule.yaml
"""


def format_validation_results(
    errors: list[ValidationError], filepath: str
) -> str:
    """Return formatted validation output for the CLI."""
    parts: list[str] = []
    parts.append(f"\n  Validating {filepath}...")
    parts.append("")

    if not errors:
        parts.append("  OK — no issues found.")
        parts.append("")
        return "\n".join(parts)

    for err in errors:
        label = "ERROR" if err.severity == "error" else "WARN "
        parts.append(f"  {label}  {err.path}")
        parts.append(f"         {err.message}")
        if err.suggestion:
            parts.append(f"         {err.suggestion}")
        parts.append("")

    n_errors = sum(1 for e in errors if e.severity == "error")
    n_warnings = sum(1 for e in errors if e.severity == "warning")
    summary_parts = []
    if n_errors:
        summary_parts.append(f"{n_errors} error{'s' if n_errors != 1 else ''}")
    if n_warnings:
        summary_parts.append(f"{n_warnings} warning{'s' if n_warnings != 1 else ''}")
    parts.append(f"  {', '.join(summary_parts)}")
    parts.append("")

    return "\n".join(parts)
