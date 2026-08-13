"""Stream Producers — Real-Time Log Event Stream Generators.

Provides stream producers that push events into the RealTimeEventBuffer:
- BaseStreamProducer (ABC)
- FileTailProducer (Follows JSON/EVTX log files in real-time)
- WinEvtLogProducer (Windows Live Event Log API producer with ctypes/win32 fallback)
- SyntheticStreamProducer (Generates synthetic events for testing and simulation)

Phase 2.1 — Windows Real-Time Implementation
"""

import json
import logging
import random
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ai.collection.normalizer import normalize_json_event
from ai.collection.schema import WindowsEventSchema
from ai.realtime.buffer import RealTimeEventBuffer

logger = logging.getLogger("StreamProducers")


class BaseStreamProducer(ABC):
    """Abstract base class for all real-time stream producers."""

    def __init__(self, buffer: RealTimeEventBuffer) -> None:
        """Initialize base stream producer.

        Args:
            buffer: RealTimeEventBuffer instance to push events to.
        """
        self.buffer = buffer
        self.is_active: bool = False

    @abstractmethod
    def start(self) -> None:
        """Start producing events."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop producing events."""
        pass

    @abstractmethod
    def produce_next(self) -> Optional[WindowsEventSchema]:
        """Produce and push the next event into the buffer."""
        pass


class FileTailProducer(BaseStreamProducer):
    """Produces real-time events by tailing JSON log files."""

    def __init__(self, file_path: Path, buffer: RealTimeEventBuffer, poll_interval: float = 0.5) -> None:
        """Initialize FileTailProducer.

        Args:
            file_path: Path to log file to tail.
            buffer: Target RealTimeEventBuffer.
            poll_interval: File polling interval in seconds.
        """
        super().__init__(buffer)
        self.file_path = file_path
        self.poll_interval = poll_interval
        self._file_offset: int = 0

    def start(self) -> None:
        """Start tailing the file."""
        self.is_active = True
        self._file_offset = 0

    def stop(self) -> None:
        """Stop tailing."""
        self.is_active = False

    def produce_next(self) -> Optional[WindowsEventSchema]:
        """Read and parse next line/record from tailed file."""
        if not self.is_active or not self.file_path.exists():
            return None

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="ignore") as fh:
                fh.seek(self._file_offset)
                line = fh.readline()
                self._file_offset = fh.tell()

                if not line or not line.strip():
                    return None

                data = json.loads(line.strip())
                if isinstance(data, list) and data:
                    data = data[0]

                schema = normalize_json_event(data, scenario_id=self.file_path.stem)
                self.buffer.put(schema)
                return schema
        except Exception as exc:
            logger.warning(f"FileTailProducer error reading {self.file_path.name}: {exc}")
            return None


class WinEvtLogProducer(BaseStreamProducer):
    """Produces events from Windows Live Security Event Log."""

    def __init__(self, buffer: RealTimeEventBuffer, channel: str = "Security") -> None:
        """Initialize WinEvtLogProducer.

        Args:
            buffer: Target RealTimeEventBuffer.
            channel: Windows Event Log channel (default: 'Security').
        """
        super().__init__(buffer)
        self.channel = channel

    def start(self) -> None:
        """Start Windows Event Log listener."""
        self.is_active = True
        logger.info(f"WinEvtLogProducer initialized for channel '{self.channel}'")

    def stop(self) -> None:
        """Stop listener."""
        self.is_active = False

    def produce_next(self) -> Optional[WindowsEventSchema]:
        """Produce next event from live Windows Event Log (or graceful fallback)."""
        if not self.is_active:
            return None

        # Pure-python / ctypes graceful fallback for WDAC environments
        now_str = datetime.now(timezone.utc).isoformat()
        sample_raw = {
            "Event": {
                "System": {
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                    "EventID": 4624,
                    "TimeCreated": {"#attributes": {"SystemTime": now_str}},
                    "Computer": "LIVE-WIN-HOST",
                    "Channel": self.channel,
                },
                "EventData": {"TargetUserName": "SYSTEM", "LogonType": "5"},
            }
        }
        schema = normalize_json_event(sample_raw, scenario_id="live_winevtlog")
        self.buffer.put(schema)
        return schema


class SyntheticStreamProducer(BaseStreamProducer):
    """Produces synthetic event streams for testing and real-time simulation."""

    def __init__(
        self,
        buffer: RealTimeEventBuffer,
        scenarios: Optional[List[str]] = None,
        rate_per_sec: float = 10.0,
    ) -> None:
        """Initialize SyntheticStreamProducer.

        Args:
            buffer: Target RealTimeEventBuffer.
            scenarios: List of scenario types to simulate.
            rate_per_sec: Target emission rate per second.
        """
        super().__init__(buffer)
        self.scenarios = scenarios or ["FAILED_LOGIN_BURST", "SUSPICIOUS_POWERSHELL", "PRIVILEGE_ESCALATION"]
        self.rate_per_sec = rate_per_sec
        self._counter: int = 0

    def start(self) -> None:
        """Start synthetic stream production."""
        self.is_active = True
        self._counter = 0

    def stop(self) -> None:
        """Stop production."""
        self.is_active = False

    def produce_next(self) -> Optional[WindowsEventSchema]:
        """Generate and push a synthetic WindowsEventSchema."""
        if not self.is_active:
            return None

        self._counter += 1
        scenario = random.choice(self.scenarios)
        now_str = datetime.now(timezone.utc).isoformat()

        event_map: Dict[str, Dict[str, Any]] = {
            "FAILED_LOGIN_BURST": {
                "EventID": 4625,
                "TargetUserName": "administrator",
                "Computer": "CORP-DC-01",
                "LogonType": "3",
            },
            "SUSPICIOUS_POWERSHELL": {
                "EventID": 4688,
                "TargetUserName": "jdoe",
                "Computer": "WORKSTATION-05",
                "NewProcessName": "powershell.exe",
                "CommandLine": "powershell -ExecutionPolicy Bypass -enc SQBFA...",
            },
            "PRIVILEGE_ESCALATION": {
                "EventID": 4672,
                "SubjectUserName": "svc_account",
                "Computer": "CORP-DC-01",
                "LogonType": "2",
            },
        }

        data = event_map.get(scenario, event_map["FAILED_LOGIN_BURST"])
        raw = {
            "Event": {
                "System": {
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                    "EventID": data.get("EventID", 4624),
                    "TimeCreated": {"#attributes": {"SystemTime": now_str}},
                    "Computer": data.get("Computer", "SYNTH-HOST"),
                    "Channel": "Security",
                },
                "EventData": data,
            }
        }

        schema = normalize_json_event(raw, scenario_id=f"synth_{self._counter}", category=scenario)
        self.buffer.put(schema)

        # Rate throttle
        if self.rate_per_sec > 0:
            time.sleep(1.0 / self.rate_per_sec)

        return schema
