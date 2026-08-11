"""Real-Time Feature Extraction Bridge.

Converts live continuous Windows Security Event Log streams (WindowsEventSchema)
into real-time model feature vectors in memory. Maintains rolling window state
(failed_login_count_5m, time_delta_prev_event, session_duration) and process
heuristics (powershell, privilege escalation, unusual process parent ratio).

Phase 2.3 — Windows Real-Time Feature Extraction Bridge
"""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from threading import Lock
from typing import Any, Dict

from ai.collection.schema import WindowsEventSchema
from ai.config import ALL_FEATURE_KEYS

logger = logging.getLogger("RealTimeFeatureBridge")

# Suspicious parent-child process pairs for unusual_process_parent_ratio
_SUSPICIOUS_PARENTS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "wmiprvse.exe",
    "spoolsv.exe",
}
_SUSPICIOUS_CHILDREN = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "certutil.exe",
    "rundll32.exe",
    "bitsadmin.exe",
}


@dataclass
class RealTimeFeatureVector:
    """Extracted feature vector for a single streaming event.

    Matches ALL_FEATURE_KEYS from ai/config.py for model inference compatibility.
    """

    failed_login_count_5m: float = 0.0
    time_delta_prev_event: float = 0.0
    is_powershell_executed: float = 0.0
    privilege_escalation_flag: float = 0.0
    unusual_process_parent_ratio: float = 0.0
    session_duration: float = 0.0
    EventID: int = 0
    Provider_Name: str = ""
    LogonType: int = 0
    event_timestamp: str = ""
    computer: str = ""
    target_user: str = ""
    record_id: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert feature vector to dictionary matching model feature keys.

        Returns:
            Dictionary with feature keys and metadata.
        """
        return {
            "failed_login_count_5m": self.failed_login_count_5m,
            "time_delta_prev_event": self.time_delta_prev_event,
            "is_powershell_executed": self.is_powershell_executed,
            "privilege_escalation_flag": self.privilege_escalation_flag,
            "unusual_process_parent_ratio": self.unusual_process_parent_ratio,
            "session_duration": self.session_duration,
            "EventID": self.EventID,
            "Provider_Name": self.Provider_Name,
            "LogonType": self.LogonType,
            "event_timestamp": self.event_timestamp,
            "computer": self.computer,
            "target_user": self.target_user,
            "record_id": self.record_id,
        }

    def to_feature_dict(self) -> Dict[str, Any]:
        """Convert to strict model feature dict containing only ALL_FEATURE_KEYS."""
        return {k: getattr(self, k) for k in ALL_FEATURE_KEYS}


class RealTimeFeatureBridge:
    """Stateful rolling-window feature extractor for live event streams."""

    def __init__(self, window_seconds: float = 300.0) -> None:
        """Initialize RealTimeFeatureBridge.

        Args:
            window_seconds: Window size in seconds for failed login rolling count (default: 300s / 5m).
        """
        self.window_seconds = window_seconds
        self._failed_logins: Dict[str, deque[float]] = {}
        self._last_host_event_time: Dict[str, float] = {}
        self._user_session_start: Dict[str, float] = {}
        self._lock = Lock()

    def process_event(self, event: WindowsEventSchema) -> RealTimeFeatureVector:
        """Process a live WindowsEventSchema and return an extracted RealTimeFeatureVector.

        Args:
            event: Incoming normalized WindowsEventSchema record.

        Returns:
            Extracted RealTimeFeatureVector dataclass instance.
        """
        with self._lock:
            evt_time = self._parse_timestamp(event.timestamp)
            host_key = event.computer or "default_host"
            user_key = event.target_user or event.subject_user or "default_user"

            # 1. failed_login_count_5m (rolling window count for 4625)
            failed_count = self._update_failed_logins(event, evt_time, user_key, host_key)

            # 2. time_delta_prev_event (seconds since previous event on host)
            time_delta = self._update_time_delta(host_key, evt_time)

            # 3. is_powershell_executed (1.0 if process or command line uses powershell)
            is_ps = self._check_powershell(event)

            # 4. privilege_escalation_flag (1.0 if EventID in 4672, 4720, 4732 or privilege escalation)
            is_priv_esc = self._check_privilege_escalation(event)

            # 5. unusual_process_parent_ratio (1.0 if suspicious parent/child process pairing)
            is_unusual_parent = self._check_unusual_parent(event)

            # 6. session_duration (active session duration in seconds)
            session_dur = self._update_session_duration(event, evt_time, user_key)

            # Categorical features
            provider = event.provider_name or "Microsoft-Windows-Security-Auditing"

            return RealTimeFeatureVector(
                failed_login_count_5m=failed_count,
                time_delta_prev_event=time_delta,
                is_powershell_executed=is_ps,
                privilege_escalation_flag=is_priv_esc,
                unusual_process_parent_ratio=is_unusual_parent,
                session_duration=session_dur,
                EventID=event.event_id,
                Provider_Name=provider,
                LogonType=event.logon_type,
                event_timestamp=event.timestamp,
                computer=event.computer,
                target_user=user_key,
                record_id=event.record_id,
            )

    def reset_state(self) -> None:
        """Reset all internal state tables."""
        with self._lock:
            self._failed_logins.clear()
            self._last_host_event_time.clear()
            self._user_session_start.clear()

    # ──────────────────────────────────────────────────────────
    # Private Feature Helper Methods
    # ──────────────────────────────────────────────────────────

    def _parse_timestamp(self, ts_str: str) -> float:
        """Parse ISO 8601 timestamp string into epoch float timestamp."""
        if not ts_str:
            return datetime.now(timezone.utc).timestamp()
        try:
            # Handle standard ISO formats with 'Z' or offset
            ts_clean = ts_str.rstrip("Z")
            if "." in ts_clean:
                parts = ts_clean.split(".")
                ts_clean = f"{parts[0]}.{parts[1][:6]}"  # Truncate nanoseconds to microseconds
            dt = datetime.fromisoformat(ts_clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return datetime.now(timezone.utc).timestamp()

    def _update_failed_logins(self, event: WindowsEventSchema, evt_time: float, user_key: str, host_key: str) -> float:
        """Update and return rolling failed login count for EventID 4625."""
        tracker_key = f"{host_key}:{user_key}"
        if tracker_key not in self._failed_logins:
            self._failed_logins[tracker_key] = deque()

        q = self._failed_logins[tracker_key]

        # Record new 4625 failed login timestamp
        if event.event_id == 4625:
            q.append(evt_time)

        # Purge timestamps older than rolling window_seconds
        cutoff = evt_time - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()

        return float(len(q))

    def _update_time_delta(self, host_key: str, evt_time: float) -> float:
        """Calculate and return time difference in seconds from previous event on host."""
        if host_key in self._last_host_event_time:
            prev_time = self._last_host_event_time[host_key]
            delta = max(0.0, evt_time - prev_time)
        else:
            delta = 0.0

        self._last_host_event_time[host_key] = evt_time
        return round(delta, 3)

    def _check_powershell(self, event: WindowsEventSchema) -> float:
        """Check if event involves PowerShell execution."""
        proc = (event.process_name or "").lower()
        cmd = (event.command_line or "").lower()
        if "powershell" in proc or "pwsh" in proc or "powershell" in cmd or "pwsh" in cmd:
            return 1.0
        return 0.0

    def _check_privilege_escalation(self, event: WindowsEventSchema) -> float:
        """Check if event represents privilege escalation or privilege assignment."""
        if event.event_id in (4672, 4720, 4732, 4738, 4756):
            return 1.0
        return 0.0

    def _check_unusual_parent(self, event: WindowsEventSchema) -> float:
        """Check for suspicious parent-child process relationships."""
        proc = (event.process_name or "").lower()
        parent = (event.parent_process_name or "").lower()

        proc_basename = proc.split("\\")[-1] if "\\" in proc else proc
        parent_basename = parent.split("\\")[-1] if "\\" in parent else parent

        if parent_basename in _SUSPICIOUS_PARENTS and proc_basename in _SUSPICIOUS_CHILDREN:
            return 1.0
        return 0.0

    def _update_session_duration(self, event: WindowsEventSchema, evt_time: float, user_key: str) -> float:
        """Track and return active logon session duration in seconds."""
        if event.event_id == 4624:  # Logon
            self._user_session_start[user_key] = evt_time
            return 0.0
        elif event.event_id == 4634:  # Logoff
            if user_key in self._user_session_start:
                start = self._user_session_start.pop(user_key)
                return round(max(0.0, evt_time - start), 2)
            return 0.0
        elif user_key in self._user_session_start:
            return round(max(0.0, evt_time - self._user_session_start[user_key]), 2)

        return 0.0
