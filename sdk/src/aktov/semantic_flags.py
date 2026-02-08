"""Client-side semantic flag extraction.

Extracts structured signals from raw tool arguments so that SAFE mode
can transmit useful detection data without ever sending the raw args
themselves.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from aktov.schema import SemanticFlags

# ---------------------------------------------------------------------------
# SQL detection
# ---------------------------------------------------------------------------

_SQL_KEYS = {"query", "sql", "statement", "sql_query", "sql_statement"}

_SQL_PATTERNS: list[tuple[str, str]] = [
    (r"\bSELECT\b", "SELECT"),
    (r"\bINSERT\b", "INSERT"),
    (r"\bUPDATE\b", "UPDATE"),
    (r"\bDELETE\b", "DELETE"),
    (r"\b(CREATE|DROP|ALTER|TRUNCATE)\b", "DDL"),
]


def _detect_sql_type(args: dict[str, Any]) -> Optional[str]:
    """Return the SQL statement type if any SQL-like key is found."""
    for key in _SQL_KEYS:
        value = args.get(key)
        if not isinstance(value, str):
            continue
        upper = value.upper()
        for pattern, label in _SQL_PATTERNS:
            if re.search(pattern, upper):
                return label
        return "OTHER"
    return None


# ---------------------------------------------------------------------------
# HTTP method detection
# ---------------------------------------------------------------------------

_HTTP_METHOD_KEYS = {"method", "http_method", "request_method"}
_VALID_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _detect_http_method(args: dict[str, Any]) -> Optional[str]:
    """Return the HTTP method if present."""
    for key in _HTTP_METHOD_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value.upper() in _VALID_HTTP_METHODS:
            return value.upper()
    return None


# ---------------------------------------------------------------------------
# External domain detection
# ---------------------------------------------------------------------------

_URL_KEYS = {"url", "domain", "host", "endpoint", "base_url", "uri"}

_INTERNAL_PATTERNS = [
    re.compile(r"localhost", re.IGNORECASE),
    re.compile(r"127\.0\.0\.1"),
    re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\.internal\b", re.IGNORECASE),
    re.compile(r"\.local\b", re.IGNORECASE),
]


def _detect_is_external(args: dict[str, Any]) -> Optional[bool]:
    """Return True if a URL/host looks external, False if internal, None if no URL."""
    for key in _URL_KEYS:
        value = args.get(key)
        if not isinstance(value, str):
            continue
        for pat in _INTERNAL_PATTERNS:
            if pat.search(value):
                return False
        return True
    return None


# ---------------------------------------------------------------------------
# Sensitive directory detection
# ---------------------------------------------------------------------------

_SENSITIVE_PATTERNS = [
    re.compile(r"/etc/"),
    re.compile(r"\.ssh/"),
    re.compile(r"\.ssh$"),
    re.compile(r"\.env\b"),
    re.compile(r"\.aws/"),
    re.compile(r"\.aws$"),
    re.compile(r"\.config/"),
    re.compile(r"\.config$"),
    re.compile(r"/proc/"),
    re.compile(r"/sys/"),
    re.compile(r"\.kube/"),
    re.compile(r"\.gnupg/"),
]


def _detect_sensitive_dir(args: dict[str, Any]) -> Optional[bool]:
    """Return True if any string value references a sensitive directory."""
    for value in args.values():
        if not isinstance(value, str):
            continue
        for pat in _SENSITIVE_PATTERNS:
            if pat.search(value):
                return True
    return None


# ---------------------------------------------------------------------------
# Path traversal detection
# ---------------------------------------------------------------------------

_TRAVERSAL_PATTERN = re.compile(r"\.\./|\.\.\\")


def _detect_path_traversal(args: dict[str, Any]) -> Optional[bool]:
    """Return True if any string value contains path traversal sequences."""
    for value in args.values():
        if not isinstance(value, str):
            continue
        if _TRAVERSAL_PATTERN.search(value):
            return True
    return None


# ---------------------------------------------------------------------------
# Network call detection
# ---------------------------------------------------------------------------

_NETWORK_INDICATORS = [
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"ftp://", re.IGNORECASE),
    re.compile(r"wss?://", re.IGNORECASE),
]


def _detect_network_calls(args: dict[str, Any]) -> Optional[bool]:
    """Return True if any value contains a URL-like pattern."""
    for value in args.values():
        if not isinstance(value, str):
            continue
        for pat in _NETWORK_INDICATORS:
            if pat.search(value):
                return True
    return None


# ---------------------------------------------------------------------------
# Argument size bucketing
# ---------------------------------------------------------------------------

def _compute_argument_size_bucket(args: dict[str, Any]) -> str:
    """Classify the serialized argument size into a human-readable bucket."""
    size = len(str(args))
    if size < 1024:
        return "small"
    elif size < 10240:
        return "medium"
    elif size < 102400:
        return "large"
    else:
        return "very_large"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_semantic_flags(
    tool_name: str,
    tool_category: str,
    arguments: dict[str, Any] | None,
) -> SemanticFlags:
    """Extract all semantic flags from raw tool arguments.

    This is the main entry point used by the client.  All detection
    helpers are called and the results collected into a SemanticFlags
    model.  The raw arguments are *not* stored — only the flags.
    """
    if arguments is None:
        return SemanticFlags()

    return SemanticFlags(
        sql_statement_type=_detect_sql_type(arguments),
        http_method=_detect_http_method(arguments),
        is_external=_detect_is_external(arguments),
        sensitive_dir_match=_detect_sensitive_dir(arguments),
        has_network_calls=_detect_network_calls(arguments),
        argument_size_bucket=_compute_argument_size_bucket(arguments),
        path_traversal_detected=_detect_path_traversal(arguments),
    )
