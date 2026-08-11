"""Unit Tests — Phase 2.2: Continuous Local Windows Security Event Monitoring.

Tests the continuous background monitor components:
  - LocalSecurityLogMonitor lifecycle (START, STOP, PAUSE, RESUME)
  - Listener callback registration and event dispatching
  - Mocked polling ticks (0 Administrator rights required)
  - Checkpoint tracking across continuous polling loops
  - Monitor status and health reporting

Phase 2.2 — Continuous Local Windows Security Event Monitoring
"""

from unittest.mock import MagicMock
import time
from typing import List

import pytest

from ai.collection.live_monitor import LocalSecurityLogMonitor
from ai.collection.live_reader import LiveWindowsEventReader
from ai.collection.schema import WindowsEventSchema


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


def _make_mock_event(event_id: int = 4625, record_id: int = 1001, computer: str = "SEC-HOST") -> WindowsEventSchema:
    """Helper fixture to build valid WindowsEventSchema instances."""
    return WindowsEventSchema(
        event_id=event_id,
        record_id=record_id,
        timestamp="2026-08-11T10:00:00Z",
        computer=computer,
        channel="Security",
        target_user="administrator",
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. LocalSecurityLogMonitor Unit Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestLocalSecurityLogMonitor:
    """Tests for LocalSecurityLogMonitor class."""

    def test_monitor_initialization(self) -> None:
        """Monitor initializes with STOPPED state and zero statistics."""
        monitor = LocalSecurityLogMonitor(poll_interval_sec=0.1)
        assert monitor.state == "STOPPED"
        assert monitor.poll_interval_sec == 0.1
        assert monitor.total_polls == 0
        assert monitor.total_events_emitted == 0
        assert monitor.listener_count() == 0

    def test_invalid_interval_raises_value_error(self) -> None:
        """Monitor raises ValueError if interval <= 0."""
        with pytest.raises(ValueError, match="poll_interval_sec must be a positive float"):
            LocalSecurityLogMonitor(poll_interval_sec=0.0)

    def test_listener_registration_and_removal(self) -> None:
        """Listeners can be registered and removed."""
        monitor = LocalSecurityLogMonitor()
        received: List[WindowsEventSchema] = []

        sub_id = monitor.add_listener(lambda evt: received.append(evt))
        assert monitor.listener_count() == 1

        assert monitor.remove_listener(sub_id) is True
        assert monitor.listener_count() == 0

    def test_poll_once_dispatches_events(self) -> None:
        """poll_once fetches events from reader and dispatches to listeners."""
        mock_reader = MagicMock(spec=LiveWindowsEventReader)
        evt1 = _make_mock_event(event_id=4625, record_id=101)
        evt2 = _make_mock_event(event_id=4688, record_id=102)
        mock_reader.read_new_events.return_value = [evt1, evt2]
        mock_reader.channel = "Security"
        mock_reader.get_reader_status.return_value = {"channel": "Security", "last_record_id": 102}

        monitor = LocalSecurityLogMonitor(poll_interval_sec=0.1, reader=mock_reader)
        received: List[WindowsEventSchema] = []
        monitor.add_listener(lambda evt: received.append(evt))

        events = monitor.poll_once(batch_size=50)

        assert len(events) == 2
        assert len(received) == 2
        assert received[0].record_id == 101
        assert received[1].record_id == 102
        assert monitor.total_polls == 1
        assert monitor.total_events_emitted == 2

    def test_background_monitoring_lifecycle(self) -> None:
        """Continuous background thread polls and dispatches events."""
        mock_reader = MagicMock(spec=LiveWindowsEventReader)
        evt = _make_mock_event(event_id=4672, record_id=500)
        mock_reader.read_new_events.return_value = [evt]
        mock_reader.channel = "Security"
        mock_reader.get_reader_status.return_value = {"channel": "Security", "last_record_id": 500}

        monitor = LocalSecurityLogMonitor(poll_interval_sec=0.05, reader=mock_reader)
        received: List[WindowsEventSchema] = []
        monitor.add_listener(lambda e: received.append(e))

        # Start background polling
        monitor.start_monitoring()
        assert monitor.state == "RUNNING"

        time.sleep(0.2)  # Wait for polling ticks

        # Pause monitoring
        monitor.pause_monitoring()
        assert monitor.state == "PAUSED"

        # Resume monitoring
        monitor.resume_monitoring()
        assert monitor.state == "RUNNING"

        time.sleep(0.1)

        # Stop monitoring
        monitor.stop_monitoring()
        assert monitor.state == "STOPPED"
        assert len(received) >= 1

    def test_get_monitor_status(self) -> None:
        """get_monitor_status returns full status summary."""
        mock_reader = MagicMock(spec=LiveWindowsEventReader)
        mock_reader.channel = "Security"
        mock_reader.get_reader_status.return_value = {
            "channel": "Security",
            "is_windows": True,
            "last_record_id": 0,
            "status": "active",
        }

        monitor = LocalSecurityLogMonitor(reader=mock_reader)
        status = monitor.get_monitor_status()

        assert status["state"] == "STOPPED"
        assert status["channel"] == "Security"
        assert status["listener_count"] == 0
        assert "reader" in status

    def test_package_exports(self) -> None:
        """LocalSecurityLogMonitor is exportable from ai.collection."""
        from ai.collection import LocalSecurityLogMonitor as Monitor

        m = Monitor()
        assert m.reader.channel == "Security"
        assert m.state == "STOPPED"
