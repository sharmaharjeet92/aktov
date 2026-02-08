"""Tests for the OpenClaw session log hook and watcher.

Covers: command parsing, tool mapping, session log parsing,
incremental reads, alert evaluation, session discovery, and
real-time polling.
"""

import json
import tempfile
from pathlib import Path

import pytest


class TestOpenClawHook:
    """Tests for the OpenClaw session log hook."""

    @pytest.mark.parametrize(
        "command,expected_tool,expected_arg_key,expected_arg_value",
        [
            ("curl https://example.com/api", "http_request", "url", "https://example.com/api"),
            ("cat /etc/passwd", "read_file", "path", "/etc/passwd"),
            ("rm -rf /tmp/data", "delete_file", "path", "/tmp/data"),
            ("/usr/bin/curl https://example.com", "http_request", "url", "https://example.com"),
        ],
        ids=["curl", "cat", "rm", "path_prefix"],
    )
    def test_parse_exec_command_known(
        self, command: str, expected_tool: str,
        expected_arg_key: str, expected_arg_value: str,
    ) -> None:
        """Known commands parse into the correct tool name and args."""
        from aktov.hooks.openclaw import _parse_exec_command

        tool_name, args = _parse_exec_command(command)
        assert tool_name == expected_tool
        assert args is not None
        assert args[expected_arg_key] == expected_arg_value

    def test_parse_exec_command_unknown(self) -> None:
        """Unknown commands use the binary name as tool_name."""
        from aktov.hooks.openclaw import _parse_exec_command

        tool_name, args = _parse_exec_command("some-custom-tool --flag value")
        assert tool_name == "some-custom-tool"
        assert args["command"] == "some-custom-tool --flag value"

    def test_parse_exec_command_empty(self) -> None:
        """Empty command returns unknown."""
        from aktov.hooks.openclaw import _parse_exec_command

        tool_name, _ = _parse_exec_command("")
        assert tool_name == "unknown"

    def test_map_tool_native_read(self) -> None:
        """Native read tool maps to read_file."""
        from aktov.hooks.openclaw import _map_tool

        tool_name, _ = _map_tool("read", {"file_path": "/tmp/test.txt"})
        assert tool_name == "read_file"

    def test_map_tool_native_browser(self) -> None:
        """Native browser tool maps to http_request."""
        from aktov.hooks.openclaw import _map_tool

        tool_name, _ = _map_tool("browser", {"url": "https://example.com"})
        assert tool_name == "http_request"

    def test_map_tool_native_write(self) -> None:
        """Native write tool maps to write_file."""
        from aktov.hooks.openclaw import _map_tool

        tool_name, _ = _map_tool("write", {"file_path": "/tmp/out.txt", "content": "hi"})
        assert tool_name == "write_file"

    def test_map_tool_exec_delegates(self) -> None:
        """exec tool delegates to _parse_exec_command."""
        from aktov.hooks.openclaw import _map_tool

        tool_name, args = _map_tool("exec", {"command": "wget https://evil.com/data"})
        assert tool_name == "http_request"
        assert args is not None
        assert "url" in args

    def test_map_tool_unknown_passthrough(self) -> None:
        """Unknown native tools pass through as-is."""
        from aktov.hooks.openclaw import _map_tool

        tool_name, _ = _map_tool("some_new_tool", {"arg": "val"})
        assert tool_name == "some_new_tool"

    def test_parse_session_log_extracts_tool_uses(self) -> None:
        """Session log parsing extracts tool_use blocks."""
        from aktov.hooks.openclaw import _parse_session_log

        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            lines = [
                json.dumps({
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_123",
                            "name": "exec",
                            "input": {"command": "cat /etc/passwd"},
                        }
                    ],
                }),
                json.dumps({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_123",
                            "content": "root:x:0:0:...",
                        }
                    ],
                }),
            ]
            session_file.write_text("\n".join(lines) + "\n")

            actions, offset = _parse_session_log(session_file)
            assert len(actions) == 1
            assert actions[0]["tool_name"] == "read_file"
            assert offset > 0

    def test_parse_session_log_native_tools(self) -> None:
        """Non-exec tools (read, write, browser) are parsed correctly."""
        from aktov.hooks.openclaw import _parse_session_log

        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            lines = [
                json.dumps({
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use", "id": "t1",
                            "name": "read", "input": {"file_path": "/tmp/a.txt"},
                        },
                        {
                            "type": "tool_use", "id": "t2",
                            "name": "browser", "input": {"url": "https://example.com"},
                        },
                    ],
                }),
            ]
            session_file.write_text("\n".join(lines) + "\n")

            actions, _ = _parse_session_log(session_file)
            assert len(actions) == 2
            assert actions[0]["tool_name"] == "read_file"
            assert actions[1]["tool_name"] == "http_request"

    def test_parse_session_log_empty_file(self) -> None:
        """Empty session file returns empty list."""
        from aktov.hooks.openclaw import _parse_session_log

        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "empty.jsonl"
            session_file.write_text("")
            actions, offset = _parse_session_log(session_file)
            assert actions == []
            assert offset == 0

    def test_parse_session_log_incremental_offset(self) -> None:
        """Incremental reads via offset only return new actions."""
        from aktov.hooks.openclaw import _parse_session_log

        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"

            # Write first tool call
            line1 = json.dumps({
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "t1", "name": "read", "input": {"file_path": "/a"}},
                ],
            })
            session_file.write_text(line1 + "\n")

            actions1, offset1 = _parse_session_log(session_file, offset=0)
            assert len(actions1) == 1

            # Append second tool call
            line2 = json.dumps({
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "t2", "name": "write", "input": {"file_path": "/b"}},
                ],
            })
            with open(session_file, "a") as f:
                f.write(line2 + "\n")

            # Read only from offset
            actions2, offset2 = _parse_session_log(session_file, offset=offset1)
            assert len(actions2) == 1
            assert actions2[0]["tool_name"] == "write_file"
            assert offset2 > offset1

    def test_parse_session_log_malformed_lines(self) -> None:
        """Malformed lines are skipped gracefully."""
        from aktov.hooks.openclaw import _parse_session_log

        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            content = "not valid json\n" + json.dumps({
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "t1", "name": "read", "input": {}}],
            }) + "\n"
            session_file.write_text(content)

            actions, _ = _parse_session_log(session_file)
            assert len(actions) == 1

    def test_evaluate_and_alert_path_traversal(self, capsys: pytest.CaptureFixture) -> None:
        """_evaluate_and_alert detects path traversal in OpenClaw actions."""
        from aktov.hooks.openclaw import _evaluate_and_alert

        actions = [
            {"tool_name": "read_file", "arguments": {"path": "../../etc/passwd"}},
        ]
        count = _evaluate_and_alert("openclaw-test", actions)

        captured = capsys.readouterr()
        assert "AK-032" in captured.err
        assert count > 0

    def test_evaluate_and_alert_with_exclusion(self) -> None:
        """Exclusions file suppresses matching alerts."""
        from aktov.hooks.openclaw import _evaluate_and_alert

        actions = [
            {"tool_name": "read_file", "arguments": {"path": "/etc/passwd"}},
        ]

        # Without exclusions — should fire
        count_no_excl = _evaluate_and_alert("openclaw", actions)
        assert count_no_excl > 0

        # With exclusions — should suppress AK-031
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False,
        ) as f:
            f.write(
                "exclusions:\n"
                "  - rule_id: AK-031\n"
                '    reason: "Benign healthcheck"\n'
                "    when:\n"
                '      agent_id: "openclaw"\n'
            )
            f.flush()
            count_excl = _evaluate_and_alert(
                "openclaw", actions, exclusions_file=f.name,
            )
        assert count_excl == 0

    def test_evaluate_and_alert_empty_actions(self) -> None:
        """Empty actions list returns 0 alerts."""
        from aktov.hooks.openclaw import _evaluate_and_alert

        count = _evaluate_and_alert("openclaw-test", [])
        assert count == 0

    def test_find_sessions_no_dir(self) -> None:
        """Returns empty list when OpenClaw agents dir doesn't exist."""
        from aktov.hooks.openclaw import _find_sessions

        with tempfile.TemporaryDirectory() as tmpdir:
            result = _find_sessions(Path(tmpdir) / "nonexistent")
            assert result == []

    def test_find_sessions_with_files(self) -> None:
        """Finds session files across multiple agents."""
        from aktov.hooks.openclaw import _find_sessions

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            # Create two agents with sessions
            (base / "agents" / "agent1" / "sessions").mkdir(parents=True)
            (base / "agents" / "agent2" / "sessions").mkdir(parents=True)
            (base / "agents" / "agent1" / "sessions" / "s1.jsonl").write_text("")
            (base / "agents" / "agent2" / "sessions" / "s2.jsonl").write_text("")

            result = _find_sessions(base)
            assert len(result) == 2

    def test_save_to_aktov_traces(self) -> None:
        """Actions are saved to ~/.aktov/traces/ for aktov report."""
        import aktov.hooks.openclaw as oc_mod
        from aktov.hooks.openclaw import _save_to_aktov_traces
        original_dir = oc_mod.TRACES_DIR

        with tempfile.TemporaryDirectory() as tmpdir:
            oc_mod.TRACES_DIR = Path(tmpdir)
            try:
                actions = [
                    {"tool_name": "read_file", "arguments": {"path": "/tmp/test"}},
                    {"tool_name": "http_request", "arguments": {"url": "https://example.com"}},
                ]
                trace_file = _save_to_aktov_traces("test-session", actions)
                assert trace_file.exists()
                lines = trace_file.read_text().strip().splitlines()
                assert len(lines) == 2
            finally:
                oc_mod.TRACES_DIR = original_dir


class TestOpenClawWatcher:
    """Tests for the OpenClaw real-time watcher components."""

    def test_stdlib_poller_detects_new_content(self) -> None:
        """StdlibPoller detects appended tool calls."""
        from aktov.hooks.openclaw import _StdlibPoller

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            sessions_dir = base / "agents" / "test" / "sessions"
            sessions_dir.mkdir(parents=True)
            session_file = sessions_dir / "session.jsonl"
            session_file.write_text("")

            poller = _StdlibPoller(openclaw_dir=base)

            # No new content yet
            results = poller.poll_once()
            assert results == []

            # Append a tool call
            line = json.dumps({
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "t1", "name": "exec", "input": {"command": "ls"}},
                ],
            })
            with open(session_file, "a") as f:
                f.write(line + "\n")

            results = poller.poll_once()
            assert len(results) == 1
            path, actions = results[0]
            assert len(actions) == 1

    def test_stdlib_poller_ignores_non_tool_lines(self) -> None:
        """StdlibPoller skips lines without tool_use blocks."""
        from aktov.hooks.openclaw import _StdlibPoller

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            sessions_dir = base / "agents" / "test" / "sessions"
            sessions_dir.mkdir(parents=True)
            session_file = sessions_dir / "session.jsonl"
            session_file.write_text("")

            poller = _StdlibPoller(openclaw_dir=base)

            # Append non-tool-use lines
            lines = [
                json.dumps({"role": "user", "content": "Hello"}),
                json.dumps({"role": "assistant", "content": "Hi there!"}),
            ]
            with open(session_file, "a") as f:
                for line in lines:
                    f.write(line + "\n")

            results = poller.poll_once()
            assert results == []
