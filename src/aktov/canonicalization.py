"""Tool category auto-mapping and canonicalization helpers.

Maps framework-specific tool names to Aktov's canonical category
taxonomy so that rules can be written against categories rather than
brittle tool names.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Default tool → category mapping
# ---------------------------------------------------------------------------

DEFAULT_TOOL_CATEGORY_MAP: dict[str, str] = {
    # Read operations
    "read_file": "read",
    "read_document": "read",
    "get_file": "read",
    "cat_file": "read",
    "list_files": "read",
    "list_directory": "read",
    "search_files": "read",
    "query_database": "read",
    "execute_sql": "read",
    "sql_query": "read",
    "get_record": "read",
    # Claude Code / agent IDE tools
    "read": "read",
    "glob": "read",
    "grep": "read",
    "taskoutput": "read",
    # Write operations
    "write_file": "write",
    "create_file": "write",
    "update_file": "write",
    "save_file": "write",
    "append_file": "write",
    "insert_record": "write",
    "update_record": "write",
    "upsert_record": "write",
    "write": "write",
    "edit": "write",
    "notebookedit": "write",
    "todowrite": "write",
    # Execute operations
    "execute_code": "execute",
    "run_command": "execute",
    "run_script": "execute",
    "shell_exec": "execute",
    "eval_code": "execute",
    "execute_python": "execute",
    "bash": "execute",
    "skill": "execute",
    # Network operations
    "http_request": "network",
    "http_get": "network",
    "http_post": "network",
    "http_put": "network",
    "http_delete": "network",
    "send_email": "network",
    "send_message": "network",
    "webhook_call": "network",
    "api_call": "network",
    "fetch_url": "network",
    "webfetch": "network",
    "websearch": "network",
    # Credential operations
    "get_credentials": "credential",
    "get_secret": "credential",
    "read_secret": "credential",
    "fetch_token": "credential",
    "get_api_key": "credential",
    "vault_read": "credential",
    # PII operations
    "get_user_info": "pii",
    "lookup_user": "pii",
    "get_personal_data": "pii",
    "read_profile": "pii",
    # Delete operations
    "delete_file": "delete",
    "remove_file": "delete",
    "delete_record": "delete",
    "drop_table": "delete",
    "purge_data": "delete",
    "truncate_table": "delete",
}


def infer_tool_category(
    tool_name: str,
    custom_map: dict[str, str] | None = None,
) -> str:
    """Infer the canonical tool category from a tool name.

    Lookup order:
      1. ``custom_map`` (user-supplied overrides)
      2. ``DEFAULT_TOOL_CATEGORY_MAP``
      3. Fallback to ``"execute"``

    The lookup is case-insensitive: both the tool name and map keys are
    lowered before comparison.
    """
    lower_name = tool_name.lower()

    if custom_map:
        for key, value in custom_map.items():
            if key.lower() == lower_name:
                return value

    for key, value in DEFAULT_TOOL_CATEGORY_MAP.items():
        if key.lower() == lower_name:
            return value

    return "execute"


def compute_argument_size_bucket(arguments: dict[str, Any] | None) -> str:
    """Classify serialized argument size into a human-readable bucket.

    Buckets:
      - ``small``:      < 1 KB
      - ``medium``:     1–10 KB
      - ``large``:      10–100 KB
      - ``very_large``: > 100 KB
    """
    if arguments is None:
        return "small"

    size = len(str(arguments))
    if size < 1024:
        return "small"
    elif size < 10_240:
        return "medium"
    elif size < 102_400:
        return "large"
    else:
        return "very_large"
