"""Tests for the rule validator module."""

import importlib.resources

import yaml
from aktov.rules.validator import (
    ACTION_FIELDS,
    TRACE_LEVEL_FIELDS,
    VALID_MATCH_TYPES,
    VALID_OPERATORS,
    ValidationError,
    format_examples_output,
    format_schema_output,
    format_validation_results,
    validate_rule,
)

# ---------------------------------------------------------------------------
# Required top-level fields
# ---------------------------------------------------------------------------

class TestValidateRequiredFields:
    """Tests for top-level required field validation."""

    def test_missing_rule_id_returns_error(self) -> None:
        errors = validate_rule({"name": "test", "match": {"conditions": []}})
        assert any(e.path == "rule_id" and e.severity == "error" for e in errors)

    def test_missing_name_returns_error(self) -> None:
        errors = validate_rule({"rule_id": "X-001", "match": {"conditions": []}})
        assert any(e.path == "name" and e.severity == "error" for e in errors)

    def test_missing_match_returns_error(self) -> None:
        errors = validate_rule({"rule_id": "X-001", "name": "test"})
        assert any(e.path == "match" and e.severity == "error" for e in errors)

    def test_valid_minimal_rule_no_errors(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test_rule",
            "match": {
                "conditions": [
                    {"field": "agent_type", "equals": "test"},
                ],
            },
        }
        errors = validate_rule(rule)
        assert not any(e.severity == "error" for e in errors)

    def test_id_alias_accepted(self) -> None:
        """'id' works as alias for 'rule_id'."""
        rule = {
            "id": "X-001",
            "name": "test_rule",
            "match": {
                "conditions": [
                    {"field": "agent_type", "equals": "test"},
                ],
            },
        }
        errors = validate_rule(rule)
        assert not any(e.severity == "error" for e in errors)


# ---------------------------------------------------------------------------
# Severity validation
# ---------------------------------------------------------------------------

class TestValidateSeverity:
    """Tests for severity field validation."""

    def test_valid_severity_no_warning(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "severity": "critical",
            "match": {"conditions": [{"field": "agent_type", "equals": "x"}]},
        }
        errors = validate_rule(rule)
        assert not any(e.path == "severity" for e in errors)

    def test_invalid_severity_warning(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "severity": "crit",
            "match": {"conditions": [{"field": "agent_type", "equals": "x"}]},
        }
        errors = validate_rule(rule)
        severity_errors = [e for e in errors if e.path == "severity"]
        assert len(severity_errors) == 1
        assert severity_errors[0].severity == "warning"
        assert "crit" in severity_errors[0].message


# ---------------------------------------------------------------------------
# Field path validation
# ---------------------------------------------------------------------------

class TestValidateFieldPaths:
    """Tests for field path validation and typo suggestions."""

    def test_known_trace_level_field(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [{"field": "agent_type", "equals": "x"}]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_known_action_level_field(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [{"field": "actions[*].tool_category", "equals": "read"}]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_nested_semantic_flags_field(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [
                {"field": "actions[*].semantic_flags.is_external", "equals": True},
            ]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_unknown_field_returns_error(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [{"field": "actions[*].nonexistent", "equals": "x"}]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert any("Unknown field" in e.message for e in errors)

    def test_typo_suggests_correction(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [{"field": "actions[*].tool_categry", "equals": "read"}]},
        }
        errors = validate_rule(rule)
        field_errors = [e for e in errors if "Unknown field" in e.message]
        assert len(field_errors) == 1
        assert "tool_category" in field_errors[0].suggestion

    def test_actions_index_prefix(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [{"field": "actions[0].tool_name", "equals": "read_file"}]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_bare_field_legacy_format(self) -> None:
        """Bare field paths (no prefix) are accepted as legacy."""
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [{"field": "tool_category", "equals": "read"}]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_outcome_nested_field(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [
                {"field": "actions[*].outcome.status", "equals": "error"},
            ]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors


# ---------------------------------------------------------------------------
# Operator validation
# ---------------------------------------------------------------------------

class TestValidateOperators:
    """Tests for operator validation."""

    def test_valid_equals_operator(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [{"field": "agent_type", "equals": "test"}]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_valid_in_operator(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [{"field": "agent_type", "in": ["a", "b"]}]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_valid_not_in_operator(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [{"field": "agent_type", "not_in": ["bad"]}]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_valid_contains_any_operator(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [
                {"field": "actions[*].tool_category", "contains_any": ["credential"]},
            ]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_valid_greater_than_operator(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [{"field": "action_count", "greater_than": 50}]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_no_operator_returns_error(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [{"field": "agent_type"}]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert any("No operator" in e.message for e in errors)

    def test_legacy_operator_accepted(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [
                {"field": "agent_type", "operator": "eq", "value": "test"},
            ]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        # Should not have "No operator" error
        assert not any("No operator" in e.message for e in errors)


# ---------------------------------------------------------------------------
# Match type validation
# ---------------------------------------------------------------------------

class TestValidateMatchTypes:
    """Tests for match type validation."""

    def test_no_match_type_returns_error(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"logic": "ALL"},
        }
        errors = validate_rule(rule)
        assert any("No match type" in e.message for e in errors)

    def test_valid_conditions_match(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"conditions": [{"field": "agent_type", "equals": "x"}]},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_valid_sequence_match(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {
                "sequence": [
                    {"step": "s1", "condition": {"field": "tool_category", "equals": "read"}},
                    {"step": "s2", "condition": {"field": "tool_category", "equals": "network"}},
                ],
            },
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_valid_consecutive_match(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {
                "consecutive": {
                    "field": "actions[*].outcome.status",
                    "in": ["failure", "error"],
                    "min_count": 3,
                },
            },
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors

    def test_valid_count_match(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {
                "count": {
                    "conditions": [{"field": "tool_category", "equals": "credential"}],
                    "min_count": 3,
                },
            },
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert not errors


# ---------------------------------------------------------------------------
# Sequence-specific validation
# ---------------------------------------------------------------------------

class TestValidateSequence:
    """Tests specific to sequence match validation."""

    def test_step_missing_condition(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {
                "sequence": [{"step": "s1"}],
            },
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert any("condition" in e.message.lower() for e in errors)

    def test_invalid_semantic_flag_name(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {
                "sequence": [
                    {
                        "step": "s1",
                        "condition": {"field": "tool_category", "equals": "network"},
                        "semantic_flags": {"is_exteranl": True},
                    },
                ],
            },
        }
        errors = validate_rule(rule)
        flag_errors = [e for e in errors if "semantic flag" in e.message.lower()]
        assert len(flag_errors) == 1
        assert "is_external" in flag_errors[0].suggestion

    def test_step_missing_equals(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {
                "sequence": [
                    {"step": "s1", "condition": {"field": "tool_category"}},
                ],
            },
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert any("equals" in e.message.lower() for e in errors)


# ---------------------------------------------------------------------------
# Consecutive-specific validation
# ---------------------------------------------------------------------------

class TestValidateConsecutive:
    """Tests specific to consecutive match validation."""

    def test_missing_field(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"consecutive": {"in": ["error"], "min_count": 3}},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert any("field" in e.path for e in errors)

    def test_missing_in_list(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"consecutive": {"field": "outcome.status", "min_count": 3}},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert any("in" in e.path for e in errors)

    def test_missing_min_count(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"consecutive": {"field": "outcome.status", "in": ["error"]}},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert any("min_count" in e.path for e in errors)


# ---------------------------------------------------------------------------
# Count-specific validation
# ---------------------------------------------------------------------------

class TestValidateCount:
    """Tests specific to count match validation."""

    def test_missing_conditions(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"count": {"min_count": 3}},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert any("conditions" in e.path for e in errors)

    def test_missing_min_count_and_min_distinct(self) -> None:
        rule = {
            "rule_id": "X-001",
            "name": "test",
            "match": {"count": {"conditions": [{"field": "tool_name", "equals": "x"}]}},
        }
        errors = [e for e in validate_rule(rule) if e.severity == "error"]
        assert any("min_count" in e.message or "min_distinct" in e.message for e in errors)


# ---------------------------------------------------------------------------
# Bundled rules pass validation (regression guard)
# ---------------------------------------------------------------------------

class TestValidateRealRules:
    """Validate that all bundled sample rules pass validation."""

    def test_ak007_passes(self) -> None:
        samples = importlib.resources.files("aktov.rules") / "samples"
        with importlib.resources.as_file(samples / "AK-007.yaml") as p:
            data = yaml.safe_load(p.read_text())
        errors = [e for e in validate_rule(data) if e.severity == "error"]
        assert not errors, errors

    def test_ak010_passes(self) -> None:
        samples = importlib.resources.files("aktov.rules") / "samples"
        with importlib.resources.as_file(samples / "AK-010.yaml") as p:
            data = yaml.safe_load(p.read_text())
        errors = [e for e in validate_rule(data) if e.severity == "error"]
        assert not errors, errors

    def test_ak032_passes(self) -> None:
        samples = importlib.resources.files("aktov.rules") / "samples"
        with importlib.resources.as_file(samples / "AK-032.yaml") as p:
            data = yaml.safe_load(p.read_text())
        errors = [e for e in validate_rule(data) if e.severity == "error"]
        assert not errors, errors

    def test_all_bundled_rules_pass(self) -> None:
        """Load every YAML in samples/ and ensure none have errors."""
        samples = importlib.resources.files("aktov.rules") / "samples"
        with importlib.resources.as_file(samples) as samples_dir:
            for f in sorted(samples_dir.glob("*.yaml")):
                data = yaml.safe_load(f.read_text())
                errors = [e for e in validate_rule(data) if e.severity == "error"]
                assert not errors, f"{f.name}: {errors}"


# ---------------------------------------------------------------------------
# Formatting tests
# ---------------------------------------------------------------------------

class TestFormatting:
    """Tests for CLI output formatting functions."""

    def test_schema_output_contains_all_sections(self) -> None:
        output = format_schema_output()
        assert "FIELDS (trace-level)" in output
        assert "FIELDS (action-level" in output
        assert "OPERATORS" in output
        assert "MATCH TYPES" in output
        assert "aktov rules examples" in output

    def test_schema_fields_only(self) -> None:
        output = format_schema_output("fields")
        assert "FIELDS" in output
        assert "OPERATORS" not in output
        assert "MATCH TYPES" not in output

    def test_schema_operators_only(self) -> None:
        output = format_schema_output("operators")
        assert "OPERATORS" in output
        assert "FIELDS" not in output

    def test_schema_match_types_only(self) -> None:
        output = format_schema_output("match-types")
        assert "MATCH TYPES" in output
        assert "FIELDS" not in output

    def test_schema_lists_all_trace_fields(self) -> None:
        output = format_schema_output("fields")
        for field_name in TRACE_LEVEL_FIELDS:
            assert field_name in output

    def test_schema_lists_all_action_fields(self) -> None:
        output = format_schema_output("fields")
        for field_name in ACTION_FIELDS:
            assert field_name in output

    def test_schema_lists_all_operators(self) -> None:
        output = format_schema_output("operators")
        for op_name in VALID_OPERATORS:
            assert op_name in output

    def test_schema_lists_all_match_types(self) -> None:
        output = format_schema_output("match-types")
        for mt_name in VALID_MATCH_TYPES:
            assert mt_name in output

    def test_examples_output_has_all_match_types(self) -> None:
        output = format_examples_output()
        assert "conditions" in output
        assert "sequence" in output
        assert "consecutive" in output
        assert "count" in output
        assert "rule_id:" in output

    def test_validation_results_ok(self) -> None:
        output = format_validation_results([], "test.yaml")
        assert "OK" in output

    def test_validation_results_with_errors(self) -> None:
        errors = [
            ValidationError(path="match.conditions[0].field", message="Unknown field 'foo'"),
            ValidationError(path="severity", message="Bad value", severity="warning"),
        ]
        output = format_validation_results(errors, "bad.yaml")
        assert "ERROR" in output
        assert "WARN" in output
        assert "1 error" in output
        assert "1 warning" in output
