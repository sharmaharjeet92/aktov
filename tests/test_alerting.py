"""Tests for the universal alert notification system.

Covers:
- File-based alert logging (Layer 1)
- on_alert callback (Layer 2)
- aktov alerts CLI (Layer 3)
- Integration with Trace.end()
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from aktov.alerting import clear_alerts, log_alerts, read_alerts

# ---------------------------------------------------------------------------
# Layer 1: File-based alert logging
# ---------------------------------------------------------------------------


class TestLogAlerts:
    """Tests for log_alerts()."""

    def test_alerts_logged_to_file(self, tmp_path: Path) -> None:
        alerts = [
            {"rule_id": "AK-010", "rule_name": "Read-Then-Network", "severity": "critical"},
        ]
        log_file = tmp_path / "alerts.jsonl"

        with patch("aktov.alerting.ALERT_LOG", log_file):
            log_alerts(
                alerts,
                agent_id="test-agent",
                agent_type="langchain",
                session_id="sess-1",
            )

        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["rule_id"] == "AK-010"
        assert entry["agent_id"] == "test-agent"
        assert entry["agent_type"] == "langchain"
        assert entry["session_id"] == "sess-1"
        assert "timestamp" in entry

    def test_multiple_alerts_logged(self, tmp_path: Path) -> None:
        alerts = [
            {"rule_id": "AK-010", "severity": "critical"},
            {"rule_id": "AK-031", "severity": "high"},
        ]
        log_file = tmp_path / "alerts.jsonl"

        with patch("aktov.alerting.ALERT_LOG", log_file):
            log_alerts(
                alerts,
                agent_id="a",
                agent_type="t",
                session_id="s",
            )

        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 2

    def test_empty_alerts_no_write(self, tmp_path: Path) -> None:
        log_file = tmp_path / "alerts.jsonl"

        with patch("aktov.alerting.ALERT_LOG", log_file):
            log_alerts([], agent_id="a", agent_type="t", session_id="s")

        assert not log_file.exists()

    def test_log_file_created_if_missing(self, tmp_path: Path) -> None:
        log_file = tmp_path / "subdir" / "alerts.jsonl"

        with patch("aktov.alerting.ALERT_LOG", log_file):
            log_alerts(
                [{"rule_id": "AK-010"}],
                agent_id="a",
                agent_type="t",
                session_id="s",
            )

        assert log_file.exists()

    def test_io_error_does_not_crash(self) -> None:
        """log_alerts should never raise, even on I/O errors."""
        with patch("aktov.alerting.ALERT_LOG", Path("/nonexistent/readonly/alerts.jsonl")):
            # Should not raise
            log_alerts(
                [{"rule_id": "AK-010"}],
                agent_id="a",
                agent_type="t",
                session_id="s",
            )

    def test_append_mode(self, tmp_path: Path) -> None:
        """Multiple calls append, not overwrite."""
        log_file = tmp_path / "alerts.jsonl"

        with patch("aktov.alerting.ALERT_LOG", log_file):
            log_alerts([{"rule_id": "AK-010"}], agent_id="a", agent_type="t", session_id="s1")
            log_alerts([{"rule_id": "AK-031"}], agent_id="a", agent_type="t", session_id="s2")

        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["rule_id"] == "AK-010"
        assert json.loads(lines[1])["rule_id"] == "AK-031"


# ---------------------------------------------------------------------------
# read_alerts + clear_alerts
# ---------------------------------------------------------------------------


class TestReadAlerts:
    """Tests for read_alerts() and clear_alerts()."""

    def _write_alerts(self, log_file: Path, entries: list[dict]) -> None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry, default=str) + "\n")

    def test_read_all_alerts(self, tmp_path: Path) -> None:
        log_file = tmp_path / "alerts.jsonl"
        now = datetime.now(UTC).isoformat()
        self._write_alerts(log_file, [
            {"timestamp": now, "rule_id": "AK-010", "severity": "critical"},
            {"timestamp": now, "rule_id": "AK-031", "severity": "high"},
        ])

        with patch("aktov.alerting.ALERT_LOG", log_file):
            alerts = read_alerts()

        assert len(alerts) == 2

    def test_read_with_since_filter(self, tmp_path: Path) -> None:
        log_file = tmp_path / "alerts.jsonl"
        old_ts = (datetime.now(UTC) - timedelta(hours=48)).isoformat()
        new_ts = datetime.now(UTC).isoformat()
        self._write_alerts(log_file, [
            {"timestamp": old_ts, "rule_id": "AK-OLD", "severity": "low"},
            {"timestamp": new_ts, "rule_id": "AK-NEW", "severity": "high"},
        ])

        since = datetime.now(UTC) - timedelta(hours=1)
        with patch("aktov.alerting.ALERT_LOG", log_file):
            alerts = read_alerts(since=since)

        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "AK-NEW"

    def test_read_with_severity_filter(self, tmp_path: Path) -> None:
        log_file = tmp_path / "alerts.jsonl"
        now = datetime.now(UTC).isoformat()
        self._write_alerts(log_file, [
            {"timestamp": now, "rule_id": "AK-LOW", "severity": "low"},
            {"timestamp": now, "rule_id": "AK-MED", "severity": "medium"},
            {"timestamp": now, "rule_id": "AK-HIGH", "severity": "high"},
            {"timestamp": now, "rule_id": "AK-CRIT", "severity": "critical"},
        ])

        with patch("aktov.alerting.ALERT_LOG", log_file):
            alerts = read_alerts(min_severity="high")

        assert len(alerts) == 2
        rule_ids = [a["rule_id"] for a in alerts]
        assert "AK-HIGH" in rule_ids
        assert "AK-CRIT" in rule_ids

    def test_read_empty_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "alerts.jsonl"
        log_file.write_text("")

        with patch("aktov.alerting.ALERT_LOG", log_file):
            alerts = read_alerts()

        assert alerts == []

    def test_read_nonexistent_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "does_not_exist.jsonl"

        with patch("aktov.alerting.ALERT_LOG", log_file):
            alerts = read_alerts()

        assert alerts == []

    def test_clear_alerts(self, tmp_path: Path) -> None:
        log_file = tmp_path / "alerts.jsonl"
        self._write_alerts(log_file, [
            {"timestamp": "2026-01-01", "rule_id": "AK-010"},
        ])
        assert log_file.stat().st_size > 0

        with patch("aktov.alerting.ALERT_LOG", log_file):
            clear_alerts()

        assert log_file.read_text() == ""

    def test_clear_nonexistent_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "does_not_exist.jsonl"

        with patch("aktov.alerting.ALERT_LOG", log_file):
            clear_alerts()  # Should not raise


# ---------------------------------------------------------------------------
# Layer 2: on_alert callback
# ---------------------------------------------------------------------------


class TestOnAlertCallback:
    """Tests for the on_alert callback parameter."""

    def test_callback_called_for_each_alert(self) -> None:
        received: list[dict] = []

        from aktov.client import Aktov

        ak = Aktov(
            agent_id="test",
            agent_type="custom",
            on_alert=lambda a: received.append(a),
            alert_log=False,
        )
        trace = ak.start_trace()
        # Trigger AK-031: sensitive file access
        trace.record_action(tool_name="read_file", arguments={"path": "/etc/passwd"})
        trace.end()

        assert len(received) > 0
        assert all("rule_id" in a for a in received)

    def test_callback_exception_caught(self) -> None:
        """on_alert errors should be caught, not propagate."""

        def bad_callback(alert: dict) -> None:
            raise RuntimeError("boom")

        from aktov.client import Aktov

        ak = Aktov(
            agent_id="test",
            agent_type="custom",
            on_alert=bad_callback,
            alert_log=False,
        )
        trace = ak.start_trace()
        trace.record_action(tool_name="read_file", arguments={"path": "/etc/passwd"})
        # Should not raise
        response = trace.end()
        assert response.alerts  # Alerts still returned despite callback failure

    def test_no_callback_no_error(self) -> None:
        """No on_alert callback should work fine."""
        from aktov.client import Aktov

        ak = Aktov(agent_id="test", agent_type="custom", alert_log=False)
        trace = ak.start_trace()
        trace.record_action(tool_name="read_file", arguments={"path": "/etc/passwd"})
        response = trace.end()
        assert isinstance(response.alerts, list)

    def test_callback_only_for_active_not_suppressed(self, tmp_path: Path) -> None:
        """on_alert should NOT fire for suppressed alerts."""
        import yaml

        received: list[dict] = []

        # Create exclusion that suppresses AK-031
        excl_file = tmp_path / "exclusions.yaml"
        excl_file.write_text(yaml.dump({
            "exclusions": [{"rule_id": "AK-031", "reason": "testing"}],
        }))

        from aktov.client import Aktov

        ak = Aktov(
            agent_id="test",
            agent_type="custom",
            on_alert=lambda a: received.append(a),
            exclusions_file=str(excl_file),
            alert_log=False,
        )
        trace = ak.start_trace()
        trace.record_action(tool_name="read_file", arguments={"path": "/etc/passwd"})
        response = trace.end()

        # AK-031 should be suppressed, not in callback
        suppressed_ids = [s["rule_id"] for s in response.suppressed_alerts]
        callback_ids = [a["rule_id"] for a in received]
        assert "AK-031" in suppressed_ids
        assert "AK-031" not in callback_ids


# ---------------------------------------------------------------------------
# alert_log=False
# ---------------------------------------------------------------------------


class TestAlertLogDisabled:
    """Test that alert_log=False skips file writes."""

    def test_alert_log_false_skips_file_write(self, tmp_path: Path) -> None:
        log_file = tmp_path / "alerts.jsonl"

        with patch("aktov.alerting.ALERT_LOG", log_file):
            from aktov.client import Aktov

            ak = Aktov(agent_id="test", agent_type="custom", alert_log=False)
            trace = ak.start_trace()
            trace.record_action(tool_name="read_file", arguments={"path": "/etc/passwd"})
            response = trace.end()

        # Alerts should still be returned, just not logged to file
        assert response.alerts
        assert not log_file.exists()


# ---------------------------------------------------------------------------
# Layer 3: CLI alerts command
# ---------------------------------------------------------------------------


class TestCLIAlerts:
    """Tests for the aktov alerts CLI command."""

    def test_alerts_command_shows_recent(self, tmp_path: Path, capsys) -> None:
        log_file = tmp_path / "alerts.jsonl"
        now = datetime.now(UTC).isoformat()
        log_file.write_text(
            json.dumps({
                "timestamp": now,
                "rule_id": "AK-010",
                "rule_name": "Test Rule",
                "severity": "critical",
                "agent_id": "test-agent",
            }) + "\n"
        )

        with patch("aktov.alerting.ALERT_LOG", log_file):
            from aktov.cli.main import main

            main(["alerts"])

        out = capsys.readouterr().out
        assert "AK-010" in out
        assert "Test Rule" in out

    def test_alerts_json_output(self, tmp_path: Path, capsys) -> None:
        log_file = tmp_path / "alerts.jsonl"
        now = datetime.now(UTC).isoformat()
        log_file.write_text(
            json.dumps({
                "timestamp": now,
                "rule_id": "AK-010",
                "severity": "high",
            }) + "\n"
        )

        with patch("aktov.alerting.ALERT_LOG", log_file):
            from aktov.cli.main import main

            main(["alerts", "--json"])

        out = capsys.readouterr().out.strip()
        parsed = json.loads(out)
        assert parsed["rule_id"] == "AK-010"

    def test_alerts_severity_filter(self, tmp_path: Path, capsys) -> None:
        log_file = tmp_path / "alerts.jsonl"
        now = datetime.now(UTC).isoformat()
        entries = [
            {"timestamp": now, "rule_id": "AK-LOW", "severity": "low", "rule_name": "Low"},
            {"timestamp": now, "rule_id": "AK-CRIT", "severity": "critical", "rule_name": "Crit"},
        ]
        log_file.write_text("\n".join(json.dumps(e) for e in entries) + "\n")

        with patch("aktov.alerting.ALERT_LOG", log_file):
            from aktov.cli.main import main

            main(["alerts", "--severity", "critical"])

        out = capsys.readouterr().out
        assert "AK-CRIT" in out
        assert "AK-LOW" not in out

    def test_alerts_clear(self, tmp_path: Path, capsys) -> None:
        log_file = tmp_path / "alerts.jsonl"
        log_file.write_text('{"rule_id": "AK-010"}\n')

        with patch("aktov.alerting.ALERT_LOG", log_file):
            from aktov.cli.main import main

            main(["alerts", "--clear"])

        assert log_file.read_text() == ""
        out = capsys.readouterr().out
        assert "cleared" in out.lower()

    def test_alerts_no_file(self, tmp_path: Path, capsys) -> None:
        log_file = tmp_path / "nonexistent.jsonl"

        with patch("aktov.alerting.ALERT_LOG", log_file):
            from aktov.cli.main import main

            main(["alerts"])

        out = capsys.readouterr().out
        assert "No alerts" in out


# ---------------------------------------------------------------------------
# Integration: alert log written during trace.end()
# ---------------------------------------------------------------------------


class TestEndToEndAlertLog:
    """Test that trace.end() writes to the alert log."""

    def test_alerts_logged_on_trace_end(self, tmp_path: Path) -> None:
        log_file = tmp_path / "alerts.jsonl"

        with patch("aktov.alerting.ALERT_LOG", log_file):
            from aktov.client import Aktov

            ak = Aktov(agent_id="e2e-agent", agent_type="custom")
            trace = ak.start_trace()
            trace.record_action(tool_name="read_file", arguments={"path": "/etc/shadow"})
            response = trace.end()

        assert response.alerts  # Should have triggered AK-031
        assert log_file.exists()
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) >= 1
        entry = json.loads(lines[0])
        assert entry["agent_id"] == "e2e-agent"
        assert "rule_id" in entry

    def test_no_alerts_no_log_write(self, tmp_path: Path) -> None:
        log_file = tmp_path / "alerts.jsonl"

        with patch("aktov.alerting.ALERT_LOG", log_file):
            from aktov.client import Aktov

            ak = Aktov(agent_id="clean-agent", agent_type="custom")
            trace = ak.start_trace()
            trace.record_action(tool_name="list_files", arguments={"dir": "/tmp"})
            response = trace.end()

        # Benign action — no alerts expected
        if not response.alerts:
            assert not log_file.exists()
