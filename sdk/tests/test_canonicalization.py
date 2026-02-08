"""Tests for aktov.canonicalization — tool category mapping."""

import pytest

from aktov.canonicalization import (
    DEFAULT_TOOL_CATEGORY_MAP,
    compute_argument_size_bucket,
    infer_tool_category,
)


class TestInferToolCategory:
    """Tests for infer_tool_category."""

    def test_read_file(self) -> None:
        assert infer_tool_category("read_file") == "read"

    def test_write_file(self) -> None:
        assert infer_tool_category("write_file") == "write"

    def test_execute_code(self) -> None:
        assert infer_tool_category("execute_code") == "execute"

    def test_http_request(self) -> None:
        assert infer_tool_category("http_request") == "network"

    def test_http_post(self) -> None:
        assert infer_tool_category("http_post") == "network"

    def test_send_email(self) -> None:
        assert infer_tool_category("send_email") == "network"

    def test_delete_file(self) -> None:
        assert infer_tool_category("delete_file") == "delete"

    def test_get_credentials(self) -> None:
        assert infer_tool_category("get_credentials") == "credential"

    def test_get_user_info(self) -> None:
        assert infer_tool_category("get_user_info") == "pii"

    def test_query_database(self) -> None:
        assert infer_tool_category("query_database") == "read"

    def test_run_command(self) -> None:
        assert infer_tool_category("run_command") == "execute"

    def test_bash(self) -> None:
        assert infer_tool_category("bash") == "execute"

    def test_fallback_to_execute(self) -> None:
        assert infer_tool_category("totally_unknown_tool") == "execute"

    def test_case_insensitive(self) -> None:
        assert infer_tool_category("READ_FILE") == "read"
        assert infer_tool_category("Write_File") == "write"

    def test_custom_map_override(self) -> None:
        custom = {"my_tool": "credential"}
        assert infer_tool_category("my_tool", custom_map=custom) == "credential"

    def test_custom_map_takes_priority(self) -> None:
        """Custom map should override the default map."""
        custom = {"read_file": "write"}
        assert infer_tool_category("read_file", custom_map=custom) == "write"

    def test_custom_map_case_insensitive(self) -> None:
        custom = {"MyTool": "network"}
        assert infer_tool_category("mytool", custom_map=custom) == "network"

    def test_custom_map_fallback_to_default(self) -> None:
        """If custom map doesn't match, fall through to default map."""
        custom = {"some_other_tool": "pii"}
        assert infer_tool_category("read_file", custom_map=custom) == "read"


class TestComputeArgumentSizeBucket:
    """Tests for compute_argument_size_bucket."""

    def test_none_is_small(self) -> None:
        assert compute_argument_size_bucket(None) == "small"

    def test_empty_dict_is_small(self) -> None:
        assert compute_argument_size_bucket({}) == "small"

    def test_small_args(self) -> None:
        assert compute_argument_size_bucket({"key": "value"}) == "small"

    def test_medium_args(self) -> None:
        args = {"data": "a" * 2000}
        assert compute_argument_size_bucket(args) == "medium"

    def test_large_args(self) -> None:
        args = {"data": "a" * 50_000}
        assert compute_argument_size_bucket(args) == "large"

    def test_very_large_args(self) -> None:
        args = {"data": "a" * 200_000}
        assert compute_argument_size_bucket(args) == "very_large"


class TestDefaultToolCategoryMap:
    """Verify the default map has adequate coverage."""

    def test_minimum_mappings(self) -> None:
        """The default map should have at least 20 entries."""
        assert len(DEFAULT_TOOL_CATEGORY_MAP) >= 20

    def test_all_categories_covered(self) -> None:
        """Every canonical category should appear at least once."""
        values = set(DEFAULT_TOOL_CATEGORY_MAP.values())
        for category in ("read", "write", "execute", "network", "credential", "pii", "delete"):
            assert category in values, f"Category '{category}' not in default map"
