"""Local rule evaluation engine.

Loads YAML rule definitions and evaluates them against trace payloads.
This enables offline / local-first detection before traces are sent to
the cloud.

Supports the full Phase 0 YAML rule schema:
- match.conditions: field-level checks on trace or actions
- match.sequence: ordered action patterns (e.g., read -> network)
- match.consecutive: N consecutive actions matching a condition
- match.count: N actions matching sub-conditions
"""

from __future__ import annotations

import importlib.resources
import logging
import os
from dataclasses import dataclass, field
from typing import Any

import yaml

from aktov.schema import Action, TracePayload

logger = logging.getLogger("aktov")


@dataclass
class Alert:
    """An alert produced when a rule matches a trace."""

    rule_id: str
    rule_name: str
    severity: str
    category: str
    matched_actions: list[int] = field(default_factory=list)
    message: str = ""


@dataclass
class YAMLRule:
    """A rule loaded from a YAML file."""

    id: str
    name: str
    severity: str = "medium"
    category: str = "general"
    match: dict[str, Any] = field(default_factory=dict)


class RuleEngine:
    """Loads YAML rules and evaluates them against traces."""

    def __init__(self) -> None:
        self._rules: list[YAMLRule] = []

    @property
    def rules(self) -> list[YAMLRule]:
        return list(self._rules)

    def load_rules(self, rules_dir: str) -> int:
        """Load all YAML rule files from a directory.

        Returns the number of rules loaded.
        """
        loaded = 0
        for filename in sorted(os.listdir(rules_dir)):
            if not filename.endswith((".yaml", ".yml")):
                continue
            filepath = os.path.join(rules_dir, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))

            for doc in docs:
                if doc is None:
                    continue
                rule = self._parse_rule(doc)
                if rule is not None:
                    self._rules.append(rule)
                    loaded += 1

        return loaded

    def load_bundled_rules(self) -> int:
        """Load the sample rules bundled with the aktov package.

        Returns the number of rules loaded.
        """
        samples = importlib.resources.files("aktov.rules") / "samples"
        with importlib.resources.as_file(samples) as samples_dir:
            return self.load_rules(str(samples_dir))

    def load_rule_from_dict(self, data: dict[str, Any]) -> YAMLRule:
        """Load a single rule from a dict (useful for testing).

        Performs strict validation — raises ``ValueError`` on errors.
        """
        from aktov.rules.validator import validate_rule

        validation_errors = [
            e for e in validate_rule(data) if e.severity == "error"
        ]
        if validation_errors:
            msgs = "; ".join(f"{e.path}: {e.message}" for e in validation_errors)
            raise ValueError(f"Invalid rule definition: {msgs}")

        rule = self._parse_rule(data)
        if rule is None:
            raise ValueError("Invalid rule definition — missing rule_id or name")
        self._rules.append(rule)
        return rule

    def evaluate(self, trace: TracePayload) -> list[Alert]:
        """Evaluate all loaded rules against a trace."""
        alerts: list[Alert] = []
        for rule in self._rules:
            alert = self._evaluate_rule(rule, trace)
            if alert is not None:
                alerts.append(alert)
        return alerts

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_rule(data: dict[str, Any]) -> YAMLRule | None:
        rule_id = data.get("rule_id") or data.get("id")
        name = data.get("name")
        if not rule_id or not name:
            return None

        # Non-blocking validation: log warnings but never crash
        try:
            from aktov.rules.validator import validate_rule

            for err in validate_rule(data):
                if err.severity == "error":
                    hint = f" ({err.suggestion})" if err.suggestion else ""
                    logger.warning(
                        "Rule %s: %s — %s%s", rule_id, err.path, err.message, hint
                    )
        except Exception:
            pass

        return YAMLRule(
            id=rule_id,
            name=name,
            severity=data.get("severity", "medium"),
            category=data.get("category", "general"),
            match=data.get("match", {}),
        )

    # ------------------------------------------------------------------
    # Evaluation dispatch
    # ------------------------------------------------------------------

    def _evaluate_rule(self, rule: YAMLRule, trace: TracePayload) -> Alert | None:
        match_block = rule.match
        if not match_block:
            return None

        actions = trace.actions
        matched: list[int] | None = None

        if "sequence" in match_block:
            matched = self._eval_sequence(match_block["sequence"], trace)
        elif "consecutive" in match_block:
            matched = self._eval_consecutive(match_block["consecutive"], actions)
        elif "count" in match_block:
            matched = self._eval_count(match_block["count"], actions)
        elif "conditions" in match_block:
            matched = self._eval_conditions(match_block["conditions"], trace)

        if matched is None:
            return None

        return Alert(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            category=rule.category,
            matched_actions=matched,
            message=f"Rule '{rule.name}' matched",
        )

    # ------------------------------------------------------------------
    # match.conditions
    # ------------------------------------------------------------------

    def _eval_conditions(
        self, conditions: list[dict[str, Any]], trace: TracePayload
    ) -> list[int] | None:
        actions = trace.actions
        all_matched: list[int] = []

        for cond in conditions:
            field_path: str = cond.get("field", "")

            # Trace-level: action_count
            if field_path == "action_count":
                if not self._check_operator(len(actions), cond):
                    return None
                continue

            # Trace-level: agent_type
            if field_path == "agent_type":
                if not self._check_operator(trace.agent_type, cond):
                    return None
                continue

            # First action: actions[0].X
            if field_path.startswith("actions[0]."):
                if not actions:
                    return None
                sub_path = field_path[len("actions[0]."):]
                actual = _resolve_field(actions[0], sub_path)
                if not self._check_operator(actual, cond):
                    return None
                all_matched.append(0)
                continue

            # Wildcard: actions[*].X — at least one action must match
            if field_path.startswith("actions[*]."):
                sub_path = field_path[len("actions[*]."):]
                found = False
                for i, action in enumerate(actions):
                    actual = _resolve_field(action, sub_path)
                    if self._check_operator(actual, cond):
                        if i not in all_matched:
                            all_matched.append(i)
                        found = True
                        break
                if not found:
                    return None
                continue

            # Direct action-level field (legacy format)
            found = False
            for i, action in enumerate(actions):
                actual = _resolve_field(action, field_path)
                if self._check_operator(actual, cond):
                    if i not in all_matched:
                        all_matched.append(i)
                    found = True
                    break
            if not found:
                return None

        return sorted(all_matched) if all_matched else [0]

    # ------------------------------------------------------------------
    # match.sequence
    # ------------------------------------------------------------------

    def _eval_sequence(
        self, steps: list[dict[str, Any]], trace: TracePayload
    ) -> list[int] | None:
        actions = trace.actions
        if not actions or not steps:
            return None

        matched: list[int] = []
        search_from = 0

        for step in steps:
            condition = step.get("condition", {})
            semantic_flags = step.get("semantic_flags", {})

            found = False
            for i in range(search_from, len(actions)):
                action = actions[i]

                # Check main condition
                field_name = condition.get("field", "")
                actual = _resolve_field(action, field_name)
                expected = condition.get("equals")
                if actual != expected:
                    continue

                # Check semantic_flags requirements
                flags_ok = True
                for flag_key, flag_val in semantic_flags.items():
                    action_flag = _resolve_field(action, f"semantic_flags.{flag_key}")
                    if action_flag != flag_val:
                        flags_ok = False
                        break

                if flags_ok:
                    matched.append(i)
                    search_from = i + 1
                    found = True
                    break

            if not found:
                return None

        return matched

    # ------------------------------------------------------------------
    # match.consecutive
    # ------------------------------------------------------------------

    def _eval_consecutive(
        self, consec_block: dict[str, Any], actions: list[Action]
    ) -> list[int] | None:
        field_path: str = consec_block.get("field", "")
        allowed_values = consec_block.get("in", [])
        min_count = consec_block.get("min_count", 3)

        # Strip actions[*]. prefix
        if field_path.startswith("actions[*]."):
            field_path = field_path[len("actions[*]."):]

        streak = 0
        streak_start = 0

        for i, action in enumerate(actions):
            actual = _resolve_field(action, field_path)
            if actual in allowed_values:
                if streak == 0:
                    streak_start = i
                streak += 1
                if streak >= min_count:
                    return list(range(streak_start, i + 1))
            else:
                streak = 0

        return None

    # ------------------------------------------------------------------
    # match.count
    # ------------------------------------------------------------------

    def _eval_count(
        self, count_block: dict[str, Any], actions: list[Action]
    ) -> list[int] | None:
        sub_conditions = count_block.get("conditions", [])
        min_count = count_block.get("min_count", 0)
        min_distinct = count_block.get("min_distinct", 0)
        threshold = max(min_count, min_distinct)

        matching: list[int] = []

        for i, action in enumerate(actions):
            all_match = True
            for sub_cond in sub_conditions:
                field_path = sub_cond.get("field", "")
                actual = _resolve_field(action, field_path)
                if not self._check_operator(actual, sub_cond):
                    all_match = False
                    break
            if all_match:
                matching.append(i)

        if threshold > 0 and len(matching) >= threshold:
            return matching

        return None

    # ------------------------------------------------------------------
    # Operator helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_operator(actual: Any, cond: dict[str, Any]) -> bool:
        """Check a single condition operator against an actual value."""
        if "equals" in cond:
            return actual == cond["equals"]

        if "in" in cond:
            return actual in cond["in"]

        if "not_in" in cond:
            return actual not in cond["not_in"]

        if "contains_any" in cond:
            expected_list = cond["contains_any"]
            if isinstance(actual, str):
                return actual in expected_list
            if isinstance(actual, list):
                return any(v in expected_list for v in actual)
            return False

        if "greater_than" in cond:
            try:
                return float(actual) > float(cond["greater_than"])
            except (TypeError, ValueError):
                return False

        if "less_than" in cond:
            try:
                return float(actual) < float(cond["less_than"])
            except (TypeError, ValueError):
                return False

        # Legacy operators
        op = cond.get("operator")
        value = cond.get("value")
        if op == "eq":
            return actual == value
        if op == "neq":
            return actual != value
        if op == "in" and isinstance(value, list):
            return actual in value
        if op == "gt":
            try:
                return float(actual) > float(value)
            except (TypeError, ValueError):
                return False
        if op == "lt":
            try:
                return float(actual) < float(value)
            except (TypeError, ValueError):
                return False
        if op == "exists":
            return actual is not None
        if op == "is_true":
            return actual is True
        if op == "is_false":
            return actual is False

        return False


def _resolve_field(action: Action, field_path: str) -> Any:
    """Resolve a dotted field path against an Action model.

    Supports paths like ``"tool_category"``,
    ``"semantic_flags.sql_statement_type"``, ``"outcome.status"``.
    """
    parts = field_path.split(".")
    obj: Any = action

    for part in parts:
        if obj is None:
            return None
        if isinstance(obj, dict):
            obj = obj.get(part)
        else:
            obj = getattr(obj, part, None)

    return obj
