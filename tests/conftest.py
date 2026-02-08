"""Shared test fixtures for the Aktov test suite."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _isolate_alert_log(tmp_path: Path):
    """Redirect alert log to a temp dir so tests never pollute ~/.aktov/alerts.jsonl."""
    fake_log = tmp_path / "test-alerts.jsonl"
    with patch("aktov.alerting.ALERT_LOG", fake_log):
        yield
