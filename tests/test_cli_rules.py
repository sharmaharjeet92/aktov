"""Tests for ``aktov rules`` CLI commands."""

import tempfile
from pathlib import Path

import pytest

from aktov.cli.main import main


# ---------------------------------------------------------------------------
# aktov rules schema
# ---------------------------------------------------------------------------

class TestRulesSchema:
    """Tests for ``aktov rules schema``."""

    def test_schema_prints_fields(self, capsys: pytest.CaptureFixture) -> None:
        main(["rules", "schema"])
        out = capsys.readouterr().out
        assert "tool_category" in out
        assert "agent_type" in out

    def test_schema_prints_operators(self, capsys: pytest.CaptureFixture) -> None:
        main(["rules", "schema"])
        out = capsys.readouterr().out
        assert "equals" in out
        assert "contains_any" in out

    def test_schema_prints_match_types(self, capsys: pytest.CaptureFixture) -> None:
        main(["rules", "schema"])
        out = capsys.readouterr().out
        assert "conditions" in out
        assert "sequence" in out

    def test_schema_fields_flag(self, capsys: pytest.CaptureFixture) -> None:
        main(["rules", "schema", "--fields"])
        out = capsys.readouterr().out
        assert "FIELDS" in out
        assert "OPERATORS" not in out

    def test_schema_operators_flag(self, capsys: pytest.CaptureFixture) -> None:
        main(["rules", "schema", "--operators"])
        out = capsys.readouterr().out
        assert "OPERATORS" in out
        assert "FIELDS" not in out

    def test_schema_match_types_flag(self, capsys: pytest.CaptureFixture) -> None:
        main(["rules", "schema", "--match-types"])
        out = capsys.readouterr().out
        assert "MATCH TYPES" in out
        assert "FIELDS" not in out


# ---------------------------------------------------------------------------
# aktov rules validate
# ---------------------------------------------------------------------------

class TestRulesValidate:
    """Tests for ``aktov rules validate``."""

    def test_valid_rule_exits_0(self, capsys: pytest.CaptureFixture) -> None:
        """Validating a bundled sample rule should pass."""
        import importlib.resources

        samples = importlib.resources.files("aktov.rules") / "samples"
        with importlib.resources.as_file(samples / "AK-007.yaml") as p:
            main(["rules", "validate", str(p)])

        out = capsys.readouterr().out
        assert "OK" in out

    def test_invalid_rule_exits_1(self, tmp_path: Path) -> None:
        """A rule with errors should exit with code 1."""
        bad_rule = tmp_path / "bad.yaml"
        bad_rule.write_text(
            "rule_id: X-001\n"
            "name: test\n"
            "match:\n"
            "  conditions:\n"
            "    - field: nonexistent_field\n"
            "      equals: true\n"
        )
        with pytest.raises(SystemExit) as exc_info:
            main(["rules", "validate", str(bad_rule)])
        assert exc_info.value.code == 1

    def test_typo_suggestion_in_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """A typo in field name should show a suggestion."""
        bad_rule = tmp_path / "typo.yaml"
        bad_rule.write_text(
            "rule_id: X-001\n"
            "name: test\n"
            "match:\n"
            "  conditions:\n"
            "    - field: actions[*].tool_categry\n"
            "      equals: read\n"
        )
        with pytest.raises(SystemExit):
            main(["rules", "validate", str(bad_rule)])

        out = capsys.readouterr().out
        assert "tool_category" in out

    def test_missing_file_shows_error(self, capsys: pytest.CaptureFixture) -> None:
        """Nonexistent file should show error on stderr."""
        with pytest.raises(SystemExit) as exc_info:
            main(["rules", "validate", "/nonexistent/path.yaml"])
        assert exc_info.value.code == 1

        err = capsys.readouterr().err
        assert "not found" in err.lower() or "File not found" in err


# ---------------------------------------------------------------------------
# aktov rules examples
# ---------------------------------------------------------------------------

class TestRulesExamples:
    """Tests for ``aktov rules examples``."""

    def test_examples_shows_all_match_types(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        main(["rules", "examples"])
        out = capsys.readouterr().out
        assert "conditions" in out
        assert "sequence" in out
        assert "consecutive" in out
        assert "count" in out

    def test_examples_shows_rule_ids(self, capsys: pytest.CaptureFixture) -> None:
        main(["rules", "examples"])
        out = capsys.readouterr().out
        assert "rule_id:" in out
