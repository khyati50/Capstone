"""Unit Tests — Phase 2.3: Real-Time Feature Extraction Bridge.

Tests the feature extraction bridge:
  - RealTimeFeatureVector dataclass structure and dictionary serialization
  - Rolling 5-minute failed login counter (failed_login_count_5m)
  - Time delta from previous event on host (time_delta_prev_event)
  - PowerShell execution detection (is_powershell_executed)
  - Privilege escalation flag (privilege_escalation_flag)
  - Suspicious parent-child process detection (unusual_process_parent_ratio)
  - Active session duration tracking (session_duration)
  - Reset state

Phase 2.3 — Windows Real-Time Feature Extraction Bridge
"""

import time

import pytest

from ai.collection.schema import WindowsEventSchema
from ai.config import ALL_FEATURE_KEYS
from ai.realtime.feature_bridge import RealTimeFeatureBridge, RealTimeFeatureVector

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


def _make_event(
    event_id: int = 4624,
    timestamp: str = "2026-08-11T10:00:00Z",
    computer: str = "CORP-DC-01",
    target_user: str = "jdoe",
    process_name: str = "",
    parent_process_name: str = "",
    command_line: str = "",
    logon_type: int = 2,
    record_id: int = 100,
) -> WindowsEventSchema:
    """Helper fixture to construct WindowsEventSchema objects."""
    return WindowsEventSchema(
        event_id=event_id,
        timestamp=timestamp,
        provider_name="Microsoft-Windows-Security-Auditing",
        computer=computer,
        channel="Security",
        target_user=target_user,
        subject_user="SYSTEM",
        process_name=process_name,
        parent_process_name=parent_process_name,
        command_line=command_line,
        source_ip="192.168.1.10",
        destination_ip="",
        logon_type=logon_type,
        scenario_id="live_stream",
        category="security_event",
        record_id=record_id,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. RealTimeFeatureVector Dataclass Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestRealTimeFeatureVector:
    """Tests for RealTimeFeatureVector class."""

    def test_feature_vector_initialization(self) -> None:
        """Dataclass initializes with safe default values."""
        vec = RealTimeFeatureVector()
        assert vec.failed_login_count_5m == 0.0
        assert vec.time_delta_prev_event == 0.0
        assert vec.is_powershell_executed == 0.0
        assert vec.EventID == 0

    def test_to_feature_dict_matches_all_feature_keys(self) -> None:
        """to_feature_dict() contains exactly ALL_FEATURE_KEYS from ai/config.py."""
        vec = RealTimeFeatureVector(
            failed_login_count_5m=3.0,
            time_delta_prev_event=1.5,
            is_powershell_executed=1.0,
            privilege_escalation_flag=0.0,
            unusual_process_parent_ratio=0.0,
            session_duration=120.0,
            EventID=4688,
            Provider_Name="Microsoft-Windows-Security-Auditing",
            LogonType=2,
        )

        f_dict = vec.to_feature_dict()

        for key in ALL_FEATURE_KEYS:
            assert key in f_dict, f"Missing feature key: {key}"
        assert f_dict["failed_login_count_5m"] == 3.0
        assert f_dict["is_powershell_executed"] == 1.0
        assert f_dict["EventID"] == 4688


# ─────────────────────────────────────────────────────────────────────────────
# 2. RealTimeFeatureBridge Extraction Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestRealTimeFeatureBridge:
    """Tests for RealTimeFeatureBridge stateful extraction methods."""

    def setup_method(self) -> None:
        """Fresh feature bridge for each test."""
        self.bridge = RealTimeFeatureBridge(window_seconds=300.0)

    def test_failed_login_count_5m_rolling_window(self) -> None:
        """failed_login_count_5m counts 4625 events within 300s window."""
        evt1 = _make_event(event_id=4625, timestamp="2026-08-11T10:00:00Z", target_user="admin", record_id=1)
        evt2 = _make_event(event_id=4625, timestamp="2026-08-11T10:01:00Z", target_user="admin", record_id=2)
        evt3 = _make_event(event_id=4625, timestamp="2026-08-11T10:02:00Z", target_user="admin", record_id=3)

        vec1 = self.bridge.process_event(evt1)
        assert vec1.failed_login_count_5m == 1.0

        vec2 = self.bridge.process_event(evt2)
        assert vec2.failed_login_count_5m == 2.0

        vec3 = self.bridge.process_event(evt3)
        assert vec3.failed_login_count_5m == 3.0

    def test_failed_login_count_purges_stale_events(self) -> None:
        """Events older than window_seconds (300s) are purged from count."""
        evt1 = _make_event(event_id=4625, timestamp="2026-08-11T10:00:00Z", target_user="admin")
        evt_stale = _make_event(event_id=4625, timestamp="2026-08-11T10:10:00Z", target_user="admin")  # 600s later

        self.bridge.process_event(evt1)
        vec_stale = self.bridge.process_event(evt_stale)

        # First event (10:00) is > 300s older than second (10:10), so count is 1.0
        assert vec_stale.failed_login_count_5m == 1.0

    def test_time_delta_prev_event(self) -> None:
        """time_delta_prev_event calculates time difference from previous host event."""
        evt1 = _make_event(event_id=4624, timestamp="2026-08-11T10:00:00Z", computer="HOST-A")
        evt2 = _make_event(event_id=4688, timestamp="2026-08-11T10:00:05Z", computer="HOST-A")

        vec1 = self.bridge.process_event(evt1)
        assert vec1.time_delta_prev_event == 0.0  # First event on host

        vec2 = self.bridge.process_event(evt2)
        assert vec2.time_delta_prev_event == 5.0  # 5 seconds delta

    def test_is_powershell_executed_flag(self) -> None:
        """is_powershell_executed returns 1.0 for PowerShell process or command line."""
        evt_normal = _make_event(event_id=4688, process_name="C:\\Windows\\explorer.exe")
        evt_ps_proc = _make_event(event_id=4688, process_name="C:\\Windows\\System32\\powershell.exe")
        evt_ps_cmd = _make_event(event_id=4688, command_line="pwsh -c 'Get-Process'")

        assert self.bridge.process_event(evt_normal).is_powershell_executed == 0.0
        assert self.bridge.process_event(evt_ps_proc).is_powershell_executed == 1.0
        assert self.bridge.process_event(evt_ps_cmd).is_powershell_executed == 1.0

    def test_privilege_escalation_flag(self) -> None:
        """privilege_escalation_flag returns 1.0 for privilege assignment EventIDs."""
        evt_4624 = _make_event(event_id=4624)
        evt_4672 = _make_event(event_id=4672)  # Special privileges assigned
        evt_4720 = _make_event(event_id=4720)  # User created
        evt_4732 = _make_event(event_id=4732)  # Group member added

        assert self.bridge.process_event(evt_4624).privilege_escalation_flag == 0.0
        assert self.bridge.process_event(evt_4672).privilege_escalation_flag == 1.0
        assert self.bridge.process_event(evt_4720).privilege_escalation_flag == 1.0
        assert self.bridge.process_event(evt_4732).privilege_escalation_flag == 1.0

    def test_unusual_process_parent_ratio(self) -> None:
        """unusual_process_parent_ratio detects suspicious parent-child process pairs."""
        evt_normal = _make_event(
            event_id=4688,
            process_name="C:\\Windows\\System32\\cmd.exe",
            parent_process_name="C:\\Windows\\explorer.exe",
        )
        evt_suspicious = _make_event(
            event_id=4688,
            process_name="C:\\Windows\\System32\\powershell.exe",
            parent_process_name="C:\\Windows\\System32\\wbem\\wmiprvse.exe",
        )

        assert self.bridge.process_event(evt_normal).unusual_process_parent_ratio == 0.0
        assert self.bridge.process_event(evt_suspicious).unusual_process_parent_ratio == 1.0

    def test_session_duration_tracking(self) -> None:
        """session_duration tracks duration of active user logon session."""
        evt_logon = _make_event(event_id=4624, timestamp="2026-08-11T10:00:00Z", target_user="alice")
        evt_activity = _make_event(event_id=4688, timestamp="2026-08-11T10:05:00Z", target_user="alice")
        evt_logoff = _make_event(event_id=4634, timestamp="2026-08-11T10:10:00Z", target_user="alice")

        vec_logon = self.bridge.process_event(evt_logon)
        assert vec_logon.session_duration == 0.0

        vec_activity = self.bridge.process_event(evt_activity)
        assert vec_activity.session_duration == 300.0  # 300 seconds active

        vec_logoff = self.bridge.process_event(evt_logoff)
        assert vec_logoff.session_duration == 600.0  # 600 seconds total at logoff

    def test_reset_state(self) -> None:
        """reset_state clears all rolling tracking tables."""
        evt = _make_event(event_id=4625, timestamp="2026-08-11T10:00:00Z", target_user="admin")
        self.bridge.process_event(evt)

        self.bridge.reset_state()

        # Next failed login starts from 1.0 after reset
        vec = self.bridge.process_event(evt)
        assert vec.failed_login_count_5m == 1.0
