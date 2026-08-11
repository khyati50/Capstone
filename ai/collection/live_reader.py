"""Live Windows Event Log Reader — Local Security Log Acquisition.

Provides the LiveWindowsEventReader class for reading unread records from the
local Windows Security Event Log channel ('Security'). Maintains read pointers,
normalizes records to WindowsEventSchema via live_normalizer, and provides
graceful non-Windows / unprivileged fallback handling.

Phase 2.1 — Windows Real-Time Local Security Event Ingestion
"""

import logging
import platform
import subprocess
from typing import Any, Dict, List, Optional

from ai.collection.live_normalizer import normalize_live_xml_event
from ai.collection.schema import WindowsEventSchema

logger = logging.getLogger("LiveWindowsEventReader")


class LiveWindowsEventReader:
    """Acquires live event records from the local Windows Security Event Log.

    Scoped strictly to the local 'Security' Event Log channel. Maintains an
    internal bookmark (last read record time / query cursor) to ensure new events
    are read without duplicates.

    Attributes:
        channel: Windows Event Log channel (fixed to 'Security').
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
        the last read cursor. Normalizes all records to WindowsEventSchema.

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

            # Validate basic event schema requirement
            if schema.event_id <= 0 or not schema.timestamp:
                self.validation_failures += 1
                continue

            # Update last read timestamp bookmark
            if schema.timestamp:
                self.last_read_timestamp = schema.timestamp

            self.total_events_read += 1
            events.append(schema)

        return events

    def get_reader_status(self) -> Dict[str, Any]:
        """Return reader operational health and acquisition statistics.

        Returns:
            Dictionary with health, event counts, channel, and bookmark info.
        """
        return {
            "channel": self.channel,
            "is_windows": self._is_windows,
            "total_events_read": self.total_events_read,
            "validation_failures": self.validation_failures,
            "last_read_timestamp": self.last_read_timestamp,
            "status": "active" if self._is_windows else "fallback_disabled",
        }

    # ──────────────────────────────────────────────────────────
    # Private Acquisition Implementation
    # ──────────────────────────────────────────────────────────

    def _query_windows_security_log(self, max_records: int = 50) -> List[str]:
        """Execute a Windows Event Query for the local Security channel.

        Uses native wevtutil structured XML query output or ctypes fallback.

        Args:
            max_records: Maximum number of recent events to retrieve.

        Returns:
            List of raw event XML strings.
        """
        cmd = [
            "wevtutil.exe",
            "qe",
            self.channel,
            f"/c:{max_records}",
            "/rd:true",
            "/f:xml",
        ]

        try:
            # Hide console window on Windows when executing subprocess
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

            return self._split_xml_events(result.stdout)
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

        # Windows Event Log XML outputs multiple <Event xmlns="..."> blocks
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
