"""Tests for aktov.semantic_flags — client-side flag extraction."""


from aktov.schema import SemanticFlags
from aktov.semantic_flags import (
    _compute_argument_size_bucket,
    _detect_http_method,
    _detect_is_external,
    _detect_network_calls,
    _detect_path_traversal,
    _detect_sensitive_dir,
    _detect_sql_type,
    extract_semantic_flags,
)


class TestSQLTypeDetection:
    """Tests for _detect_sql_type."""

    def test_select(self) -> None:
        assert _detect_sql_type({"query": "SELECT * FROM users"}) == "SELECT"

    def test_insert(self) -> None:
        assert _detect_sql_type({"sql": "INSERT INTO users VALUES (1, 'x')"}) == "INSERT"

    def test_update(self) -> None:
        assert _detect_sql_type({"statement": "UPDATE users SET name='y' WHERE id=1"}) == "UPDATE"

    def test_delete(self) -> None:
        assert _detect_sql_type({"query": "DELETE FROM users WHERE id=1"}) == "DELETE"

    def test_ddl_drop_table(self) -> None:
        assert _detect_sql_type({"query": "DROP TABLE users"}) == "DDL"

    def test_ddl_alter(self) -> None:
        assert _detect_sql_type({"sql": "ALTER TABLE users ADD COLUMN age INT"}) == "DDL"

    def test_ddl_create(self) -> None:
        assert _detect_sql_type({"query": "CREATE TABLE test (id INT)"}) == "DDL"

    def test_other_sql(self) -> None:
        assert _detect_sql_type({"query": "EXPLAIN ANALYZE something"}) == "OTHER"

    def test_no_sql_key(self) -> None:
        assert _detect_sql_type({"path": "/etc/passwd"}) is None

    def test_non_string_value(self) -> None:
        assert _detect_sql_type({"query": 123}) is None


class TestHTTPMethodDetection:
    """Tests for _detect_http_method."""

    def test_get(self) -> None:
        assert _detect_http_method({"method": "GET"}) == "GET"

    def test_post_lowercase(self) -> None:
        assert _detect_http_method({"method": "post"}) == "POST"

    def test_http_method_key(self) -> None:
        assert _detect_http_method({"http_method": "PUT"}) == "PUT"

    def test_delete(self) -> None:
        assert _detect_http_method({"method": "DELETE"}) == "DELETE"

    def test_no_method(self) -> None:
        assert _detect_http_method({"url": "https://example.com"}) is None

    def test_invalid_method(self) -> None:
        assert _detect_http_method({"method": "FETCH"}) is None


class TestExternalDomainDetection:
    """Tests for _detect_is_external."""

    def test_external_url(self) -> None:
        assert _detect_is_external({"url": "https://example.com/api"}) is True

    def test_localhost(self) -> None:
        assert _detect_is_external({"url": "http://localhost:8080/api"}) is False

    def test_loopback_ip(self) -> None:
        assert _detect_is_external({"host": "127.0.0.1"}) is False

    def test_private_10_range(self) -> None:
        assert _detect_is_external({"domain": "10.0.1.5"}) is False

    def test_private_192_range(self) -> None:
        assert _detect_is_external({"host": "192.168.1.100"}) is False

    def test_internal_domain(self) -> None:
        assert _detect_is_external({"url": "https://service.internal/api"}) is False

    def test_local_domain(self) -> None:
        assert _detect_is_external({"url": "http://myapp.local/api"}) is False

    def test_no_url_key(self) -> None:
        assert _detect_is_external({"query": "SELECT 1"}) is None


class TestSensitiveDirDetection:
    """Tests for _detect_sensitive_dir."""

    def test_etc(self) -> None:
        assert _detect_sensitive_dir({"path": "/etc/passwd"}) is True

    def test_ssh(self) -> None:
        assert _detect_sensitive_dir({"file": "/home/user/.ssh/id_rsa"}) is True

    def test_env_file(self) -> None:
        assert _detect_sensitive_dir({"path": "/app/.env"}) is True

    def test_aws_dir(self) -> None:
        assert _detect_sensitive_dir({"dir": "/home/user/.aws/credentials"}) is True

    def test_config_dir(self) -> None:
        assert _detect_sensitive_dir({"path": "/home/user/.config/secret"}) is True

    def test_proc(self) -> None:
        assert _detect_sensitive_dir({"file": "/proc/self/environ"}) is True

    def test_sys(self) -> None:
        assert _detect_sensitive_dir({"path": "/sys/kernel/debug"}) is True

    def test_normal_path(self) -> None:
        assert _detect_sensitive_dir({"path": "/home/user/documents/report.csv"}) is None

    def test_non_string_value(self) -> None:
        assert _detect_sensitive_dir({"count": 42}) is None


class TestPathTraversalDetection:
    """Tests for _detect_path_traversal."""

    def test_dot_dot_slash(self) -> None:
        assert _detect_path_traversal({"path": "../../etc/passwd"}) is True

    def test_nested_traversal(self) -> None:
        assert _detect_path_traversal({"file": "/home/user/../../../etc/shadow"}) is True

    def test_backslash_traversal(self) -> None:
        assert _detect_path_traversal({"path": "..\\windows\\system32"}) is True

    def test_normal_path(self) -> None:
        assert _detect_path_traversal({"path": "/home/user/docs/file.txt"}) is None

    def test_no_string_values(self) -> None:
        assert _detect_path_traversal({"count": 5}) is None


class TestNetworkCallDetection:
    """Tests for _detect_network_calls."""

    def test_https_url(self) -> None:
        assert _detect_network_calls({"url": "https://api.example.com"}) is True

    def test_http_url(self) -> None:
        assert _detect_network_calls({"endpoint": "http://service/api"}) is True

    def test_ftp_url(self) -> None:
        assert _detect_network_calls({"url": "ftp://files.example.com"}) is True

    def test_websocket(self) -> None:
        assert _detect_network_calls({"url": "wss://stream.example.com"}) is True

    def test_no_urls(self) -> None:
        assert _detect_network_calls({"query": "SELECT 1"}) is None


class TestArgumentSizeBucket:
    """Tests for _compute_argument_size_bucket."""

    def test_small(self) -> None:
        assert _compute_argument_size_bucket({"key": "value"}) == "small"

    def test_medium(self) -> None:
        # Create args that serialize to ~2KB
        args = {"data": "x" * 2000}
        assert _compute_argument_size_bucket(args) == "medium"

    def test_large(self) -> None:
        # Create args that serialize to ~50KB
        args = {"data": "x" * 50000}
        assert _compute_argument_size_bucket(args) == "large"

    def test_very_large(self) -> None:
        # Create args that serialize to ~200KB
        args = {"data": "x" * 200000}
        assert _compute_argument_size_bucket(args) == "very_large"


class TestExtractSemanticFlags:
    """Integration tests for the top-level extract_semantic_flags function."""

    def test_none_arguments(self) -> None:
        flags = extract_semantic_flags("read_file", "read", None)
        assert flags == SemanticFlags()

    def test_sql_query(self) -> None:
        flags = extract_semantic_flags(
            "execute_sql", "read", {"query": "SELECT * FROM users"}
        )
        assert flags.sql_statement_type == "SELECT"
        assert flags.argument_size_bucket == "small"

    def test_http_request(self) -> None:
        flags = extract_semantic_flags(
            "http_request",
            "network",
            {"method": "POST", "url": "https://api.example.com"},
        )
        assert flags.http_method == "POST"
        assert flags.is_external is True
        assert flags.has_network_calls is True

    def test_sensitive_file_read(self) -> None:
        flags = extract_semantic_flags(
            "read_file", "read", {"path": "/etc/shadow"}
        )
        assert flags.sensitive_dir_match is True

    def test_combined_flags(self) -> None:
        flags = extract_semantic_flags(
            "custom_tool",
            "execute",
            {
                "query": "DROP TABLE users",
                "url": "https://evil.com/exfil",
                "path": "../../etc/passwd",
            },
        )
        assert flags.sql_statement_type == "DDL"
        assert flags.is_external is True
        assert flags.has_network_calls is True
        assert flags.path_traversal_detected is True

