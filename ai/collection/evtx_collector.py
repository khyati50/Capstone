"""Windows Event Collector — Primary Ingestion Engine.

Provides the WindowsEventCollector class as the single authoritative ingestion
point for raw Windows Security Event Log data. Supports both binary EVTX file
ingestion (via python-evtx) and pre-converted JSON log ingestion.

All downstream pipeline layers (preprocessing, detection, explainability) must
consume events produced by this collector rather than reading files directly.

Phase 1 — Windows Event Collector Foundation
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from ai.collection.normalizer import normalize_json_event, normalize_evtx_record
from ai.collection.schema import WindowsEventSchema

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("WindowsEventCollector")


class WindowsEventCollector:
    """Primary ingestion engine for Windows Security Event Log data.

    Supports ingestion of raw EVTX binary files and pre-converted JSON log
    files produced by the Atomic-EVTX dataset. Normalizes all records to
    WindowsEventSchema, validates required fields, and tracks collection
    health statistics.

    Attributes:
        total_files_processed: Count of all files attempted.
        total_events_collected: Count of all successfully normalized events.
        total_validation_failures: Count of events that failed validation.
        failed_files: List of file paths that produced errors.
        event_id_distribution: Frequency map of collected Event IDs.
    """

    def __init__(self) -> None:
        """Initialize the WindowsEventCollector with zeroed statistics."""
        self.total_files_processed: int = 0
        self.total_events_collected: int = 0
        self.total_validation_failures: int = 0
        self.failed_files: List[str] = []
        self.event_id_distribution: Dict[int, int] = {}

    # ──────────────────────────────────────────────────────────
    # Public Collection API
    # ──────────────────────────────────────────────────────────

    def collect_from_json_file(self, json_path: Path) -> List[WindowsEventSchema]:
        """Ingest all Windows Event Log records from a single JSON file.

        The Atomic-EVTX JSON files may contain either a single event dict or
        a list of event dicts. Both formats are handled transparently.

        Args:
            json_path: Absolute path to a JSON log file.

        Returns:
            List of normalized WindowsEventSchema instances.
            Empty list if the file does not exist, is malformed, or has no
            valid events.
        """
        if not json_path.exists():
            logger.warning(f"JSON file does not exist: {json_path}")
            return []

        self.total_files_processed += 1
        scenario_id = json_path.stem
        parent = json_path.parent.name
        category = json_path.parent.parent.name if parent == "json" else parent

        raw_records: List[Dict[str, Any]] = []
        try:
            with open(json_path, "r", encoding="utf-8", errors="ignore") as fh:
                data = json.load(fh)
            raw_records = data if isinstance(data, list) else [data]
        except json.JSONDecodeError as exc:
            logger.error(f"Malformed JSON in {json_path.name}: {exc}")
            self.failed_files.append(str(json_path))
            return []
        except OSError as exc:
            logger.error(f"OS error reading {json_path.name}: {exc}")
            self.failed_files.append(str(json_path))
            return []

        collected: List[WindowsEventSchema] = []
        for raw in raw_records:
            if not isinstance(raw, dict):
                self.total_validation_failures += 1
                continue

            if not self.validate_event(raw):
                self.total_validation_failures += 1
                continue

            schema = normalize_json_event(raw, scenario_id=scenario_id, category=category)
            self._record_event_id(schema.event_id)
            collected.append(schema)

        self.total_events_collected += len(collected)
        return collected

    def collect_from_evtx_file(self, evtx_path: Path) -> List[WindowsEventSchema]:
        """Ingest all Windows Event Log records from a binary EVTX file.

        Uses the python-evtx library to iterate records. Falls back gracefully
        if the library is unavailable or the file is corrupt.

        Args:
            evtx_path: Absolute path to an EVTX binary file.

        Returns:
            List of normalized WindowsEventSchema instances.
            Empty list if the file is unreadable, corrupt, or python-evtx
            is unavailable.
        """
        if not evtx_path.exists():
            logger.warning(f"EVTX file does not exist: {evtx_path}")
            return []

        self.total_files_processed += 1
        scenario_id = evtx_path.stem

        try:
            import Evtx.Evtx as evtx  # type: ignore[import]
        except ImportError:
            logger.warning("python-evtx library not available. " "Install via: pip install python-evtx>=0.7.4")
            self.failed_files.append(str(evtx_path))
            return []

        collected: List[WindowsEventSchema] = []
        try:
            with evtx.Evtx(str(evtx_path)) as log:
                for record in log.records():
                    try:
                        schema = normalize_evtx_record(record, scenario_id=scenario_id)
                    except Exception as exc:
                        logger.warning(f"Failed to normalize EVTX record in {evtx_path.name}: {exc}")
                        self.total_validation_failures += 1
                        continue

                    if schema.event_id == 0 and not schema.timestamp:
                        self.total_validation_failures += 1
                        continue

                    self._record_event_id(schema.event_id)
                    collected.append(schema)
        except Exception as exc:
            logger.error(f"Failed to open EVTX file {evtx_path.name}: {exc}")
            self.failed_files.append(str(evtx_path))
            return []

        self.total_events_collected += len(collected)
        return collected

    def collect_from_directory(
        self,
        dir_path: Path,
        file_type: str = "json",
    ) -> List[WindowsEventSchema]:
        """Recursively collect all Windows Event Log records from a directory.

        Walks the entire directory tree and processes every file matching the
        specified file type. Files are processed in filesystem traversal order.

        Args:
            dir_path: Root directory to search recursively.
            file_type: File extension to collect — ``"json"`` (default) or
                ``"evtx"``. Case-insensitive.

        Returns:
            Flat list of all normalized WindowsEventSchema instances across
            all processed files. Empty list if directory does not exist or
            contains no matching files.

        Raises:
            ValueError: If ``file_type`` is not ``"json"`` or ``"evtx"``.
        """
        ft = file_type.lower().lstrip(".")
        if ft not in ("json", "evtx"):
            raise ValueError(f"Unsupported file_type '{file_type}'. Must be 'json' or 'evtx'.")

        if not dir_path.exists():
            logger.warning(f"Collection directory does not exist: {dir_path}")
            return []

        pattern = f"*.{ft}"
        target_files = sorted(dir_path.rglob(pattern))

        if not target_files:
            logger.warning(f"No {ft.upper()} files found under: {dir_path}")
            return []

        logger.info(f"Collecting from {len(target_files)} {ft.upper()} files in {dir_path}")

        all_events: List[WindowsEventSchema] = []
        for file_path in target_files:
            if ft == "json":
                events = self.collect_from_json_file(file_path)
            else:
                events = self.collect_from_evtx_file(file_path)
            all_events.extend(events)

        logger.info(
            f"Collection complete: {len(all_events)} events from "
            f"{self.total_files_processed} files "
            f"({self.total_validation_failures} validation failures)"
        )
        return all_events

    # ──────────────────────────────────────────────────────────
    # Validation
    # ──────────────────────────────────────────────────────────

    def validate_event(self, event: Dict[str, Any]) -> bool:
        """Validate a raw event dictionary against Phase 1 collection rules.

        An event is **valid** if ALL of the following conditions are met:
          1. ``EventID`` is present and is an integer in range 1–65535.
          2. ``TimeCreated`` is present and non-empty.
          3. ``Computer`` (hostname) is present and non-empty.

        The function also handles the Atomic-EVTX nested JSON structure where
        fields live under ``event["Event"]["System"]`` and ``event["Event"]["EventData"]``.

        Args:
            event: Raw event dictionary from a JSON or EVTX source.

        Returns:
            True if the event passes all validation rules, False otherwise.
        """
        # Unwrap nested Atomic-EVTX structure if present
        inner = event.get("Event", event)
        system = inner.get("System", inner)
        event_data = inner.get("EventData", {})

        # Rule 1: EventID must be a valid integer 1-65535
        raw_eid = system.get("EventID", event_data.get("EventID", event.get("EventID")))
        if raw_eid is None:
            logger.warning("Validation failed: missing EventID field")
            return False
        try:
            eid = int(raw_eid)
        except (ValueError, TypeError):
            logger.warning(f"Validation failed: non-integer EventID '{raw_eid}'")
            return False
        if not (1 <= eid <= 65535):
            logger.warning(f"Validation failed: EventID {eid} out of valid range 1–65535")
            return False

        # Rule 2: TimeCreated must be present and non-empty
        time_created = system.get("TimeCreated", event.get("TimeCreated", ""))
        if isinstance(time_created, dict):
            time_created = time_created.get("#attributes", {}).get("SystemTime", "")
        if not time_created:
            logger.warning(f"Validation failed: missing or empty TimeCreated for EventID {eid}")
            return False

        # Rule 3: Computer (hostname) must be present and non-empty
        computer = system.get("Computer", event.get("Computer", ""))
        if not computer or not str(computer).strip():
            logger.warning(f"Validation failed: missing Computer field for EventID {eid}")
            return False

        return True

    # ──────────────────────────────────────────────────────────
    # Statistics & Health
    # ──────────────────────────────────────────────────────────

    def get_collection_stats(self) -> Dict[str, Any]:
        """Return current collection statistics and health assessment.

        Health is computed as follows:
          - ``"healthy"``: Zero validation failures.
          - ``"degraded"``: Validation failure rate between 0% and 10% (exclusive).
          - ``"failed"``: Failure rate ≥ 10% OR zero events collected.

        Returns:
            Dictionary with keys:
                - ``total_files_processed`` (int)
                - ``total_events_collected`` (int)
                - ``total_validation_failures`` (int)
                - ``failed_files`` (List[str])
                - ``event_id_distribution`` (Dict[str, int])
                - ``collection_health`` (str): ``"healthy"``, ``"degraded"``, or ``"failed"``
        """
        total_attempted = self.total_events_collected + self.total_validation_failures
        if total_attempted == 0 or self.total_events_collected == 0:
            health = "failed"
        elif self.total_validation_failures == 0:
            health = "healthy"
        else:
            failure_rate = self.total_validation_failures / total_attempted
            health = "degraded" if failure_rate < 0.10 else "failed"

        return {
            "total_files_processed": self.total_files_processed,
            "total_events_collected": self.total_events_collected,
            "total_validation_failures": self.total_validation_failures,
            "failed_files": list(self.failed_files),
            "event_id_distribution": {str(k): v for k, v in self.event_id_distribution.items()},
            "collection_health": health,
        }

    def reset_stats(self) -> None:
        """Reset all collection statistics to zero for a fresh collection run."""
        self.total_files_processed = 0
        self.total_events_collected = 0
        self.total_validation_failures = 0
        self.failed_files = []
        self.event_id_distribution = {}

    # ──────────────────────────────────────────────────────────
    # Private Helpers
    # ──────────────────────────────────────────────────────────

    def _record_event_id(self, event_id: int) -> None:
        """Increment the frequency counter for a given Event ID.

        Args:
            event_id: Windows Event ID integer to record.
        """
        self.event_id_distribution[event_id] = self.event_id_distribution.get(event_id, 0) + 1
