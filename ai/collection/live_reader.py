"""Live Windows Event Log Reader — Local Security Log Acquisition.

Provides the LiveWindowsEventReader class for reading unread records from the
local Windows Security Event Log channel ('Security'). Maintains read pointers,
checkpointing by EventRecordID, normalizes records to WindowsEventSchema via
live_normalizer, and provides graceful non-Windows / unprivileged fallback handling.

Phase 2.1 — Windows Real-Time Local Security Event Ingestion
"""

import logging
import platform
import subprocess
import time
from typing import Any, Dict, Generator, List, Optional

from ai.collection.live_normalizer import normalize_live_xml_event
from ai.collection.schema import WindowsEventSchema

logger = logging.getLogger("LiveWindowsEventReader")


class LiveWindowsEventReader:
    """Acquires live event records from the local Windows Security Event Log.

    Scoped strictly to the local 'Security' Event Log channel. Maintains an
    internal checkpoint (last_record_id / last_read_timestamp) to ensure new events
    are read without re-emitting already-processed records.

    Attributes:
        channel: Windows Event Log channel (fixed to 'Security').
        last_record_id: Highest EventRecordID integer read so far (checkpoint cursor).
        last_read_timestamp: SystemTime string of the most recent event read.
        total_events_read: Lifetime count of events acquired.
        validation_failures: Count of records that failed schema validation.
    """

    def __init__(self, channel: str = "Security") -> None:
        """Initialize LiveWindowsEventReader.

        Args:
            channel: Target Windows Event Log channel name. Defaults to 'Security'.
        """
        self.channel = channel
        self.last_record_id: int = 0
        self.last_read_timestamp: Optional[str] = None
        self.total_events_read: int = 0
        self.validation_failures: int = 0
        self._is_windows: bool = platform.system() == "Windows"

    def is_available(self) -> bool:
        """Check if local Windows Event Log reading is supported in current environment.

        Returns:
            True if running on Windows OS, False otherwise.
        """
        return self._is_windows

    def read_new_events(self, max_records: int = 50) -> List[WindowsEventSchema]:
        """Read newly appended records from the local Security Event Log.

        Queries the local Windows Security Event Log for new records created since
        the last read cursor. Checkpoint tracking via EventRecordID prevents
        already-processed events from being emitted again.

        Args:
            max_records: Maximum number of records to fetch in this batch.

        Returns:
            List of normalized WindowsEventSchema objects.
        """
        if not self._is_windows:
            logger.info("Non-Windows OS detected: LiveWindowsEventReader operating in fallback mode.")
            return []

        xml_records = self._query_windows_security_log(max_records=max_records)
        if not xml_records:
            return []

        events: List[WindowsEventSchema] = []
        for xml_str in xml_records:
            schema = normalize_live_xml_event(xml_str, source_channel=self.channel)

            # Checkpoint filter: Skip already-processed records using EventRecordID
            if schema.record_id > 0 and schema.record_id <= self.last_record_id:
                logger.debug(f"Skipping already-processed EventRecordID {schema.record_id}")
                continue

            # Validate basic event schema requirement
            if schema.event_id <= 0 or not schema.timestamp:
                self.validation_failures += 1
                # Checkpoint MUST NOT advance on normalization/validation failure
                continue

            # Update checkpoint cursor ONLY after successful normalization & validation
            if schema.record_id > 0:
                self.last_record_id = max(self.last_record_id, schema.record_id)
            if schema.timestamp:
                self.last_read_timestamp = schema.timestamp

            self.total_events_read += 1
            events.append(schema)

        return events

    def stream_events(
        self,
        poll_interval_sec: float = 1.0,
        batch_size: int = 50,
    ) -> Generator[WindowsEventSchema, None, None]:
        """Yield new WindowsEventSchema records continuously as a Generator.

        Waits for new records without busy-looping aggressively or rescanning
        the same records. Handles Ctrl+C (KeyboardInterrupt) gracefully.

        Args:
            poll_interval_sec: Polling interval in seconds.
            batch_size: Maximum records to fetch per tick.

        Yields:
            Normalized WindowsEventSchema records.
        """
        logger.info(f"Starting continuous stream_events for local channel '{self.channel}'...")
        try:
            while True:
                events = self.read_new_events(max_records=batch_size)
                for event in events:
                    yield event
                time.sleep(poll_interval_sec)
        except (KeyboardInterrupt, SystemExit):
            logger.info("Continuous stream_events interrupted by user shutdown.")

    def get_reader_status(self) -> Dict[str, Any]:
        """Return reader operational health and acquisition statistics.

        Returns:
            Dictionary with health, event counts, channel, and bookmark info.
        """
        return {
            "channel": self.channel,
            "is_windows": self._is_windows,
            "last_record_id": self.last_record_id,
            "last_read_timestamp": self.last_read_timestamp,
            "total_events_read": self.total_events_read,
            "validation_failures": self.validation_failures,
            "status": "active" if self._is_windows else "fallback_disabled",
        }

    # ──────────────────────────────────────────────────────────
    # Private Acquisition Implementation
    # ──────────────────────────────────────────────────────────

    def _query_windows_security_log(self, max_records: int = 50) -> List[str]:
        """Execute a Windows Event Query for the local Security channel.

        Uses structured XPath EventRecordID filtering when a checkpoint exists.

        Args:
            max_records: Maximum number of recent events to retrieve.

        Returns:
            List of raw event XML strings.
        """
        cmd = ["wevtutil.exe", "qe", self.channel]

        if self.last_record_id > 0:
            xpath_query = f"*[System[EventRecordID > {self.last_record_id}]]"
            cmd.extend([f"/q:{xpath_query}", f"/c:{max_records}", "/rd:false", "/f:xml"])
        else:
            cmd.extend([f"/c:{max_records}", "/rd:true", "/f:xml"])

        try:
            startupinfo = None
            if hasattr(subprocess, "STARTUPINFO"):
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5.0,
                startupinfo=startupinfo,
                encoding="utf-8",
                errors="ignore",
            )

            if result.returncode != 0:
                logger.warning(f"wevtutil returned code {result.returncode}: {result.stderr.strip()}")
                return []

            events = self._split_xml_events(result.stdout)
            # When initial query uses /rd:true (descending), reverse so records process in ascending chronological order
            if self.last_record_id == 0:
                events.reverse()

            return events
        except subprocess.TimeoutExpired:
            logger.error("Timeout querying Windows Security Event Log via wevtutil.")
            return []
        except FileNotFoundError:
            logger.warning("wevtutil.exe not found on system path.")
            return []
        except Exception as exc:
            logger.error(f"Error querying Windows Security Event Log: {exc}")
            return []

    def _split_xml_events(self, raw_stdout: str) -> List[str]:
        """Split combined wevtutil XML output stream into individual Event XML strings.

        Args:
            raw_stdout: Raw output from wevtutil /f:xml command.

        Returns:
            List of individual event XML strings.
        """
        if not raw_stdout or not raw_stdout.strip():
            return []

        event_chunks: List[str] = []
        raw_chunks = raw_stdout.split("</Event>")

        for chunk in raw_chunks:
            chunk = chunk.strip()
            if not chunk:
                continue
            idx = chunk.find("<Event")
            if idx != -1:
                event_xml = chunk[idx:] + "</Event>"
                event_chunks.append(event_xml)

        return event_chunks


# ──────────────────────────────────────────────────────────────────────────────
# Manual Windows Smoke-Test CLI Entry Point
# Run with:  python -m ai.collection.live_reader
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 72)
    print("  Local Windows Security Event Log Reader — Phase 2.1 Smoke Test")
    print("=" * 72)

    reader = LiveWindowsEventReader(channel="Security")
    print(f"  Target Channel : {reader.channel}")
    print(f"  Is Windows OS  : {reader.is_available()}")
    print()

    print("[INFO] Querying recent Security Event Log records...")
    events = reader.read_new_events(max_records=10)
    status = reader.get_reader_status()

    print()
    print("------------------------------------------------------------------------")
    print("  ACQUISITION REPORT")
    print("------------------------------------------------------------------------")
    print(f"  Status             : {status['status'].upper()}")
    print(f"  Total Events Read  : {status['total_events_read']}")
    print(f"  Last Record ID     : {status['last_record_id']}")
    print(f"  Last Read Timestamp: {status['last_read_timestamp']}")
    print(f"  Validation Failures: {status['validation_failures']}")

    if events:
        print()
        print(f"  Acquired Events (first {min(5, len(events))}):")
        for i, evt in enumerate(events[:5], 1):
            tag = "MONITORED" if evt.is_monitored_event() else "general  "
            print(
                f"    [{i}] RecordID={evt.record_id:<8} "
                f"EventID={evt.event_id:<6} "
                f"Computer={evt.computer:<20} "
                f"User={evt.target_user or evt.subject_user:<15} [{tag}]"
            )

    print()
    print("=" * 72)
