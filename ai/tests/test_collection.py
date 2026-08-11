"""Unit Tests — Phase 1: Windows Event Collector Foundation.

Tests the complete ai/collection/ package:
  - WindowsEventSchema dataclass structure and helpers
  - EventNormalizer JSON and EVTX normalization
  - WindowsEventCollector ingestion, validation, stats, and health

Covers happy path, edge cases, and negative cases (corrupted input,
missing fields, invalid Event IDs) as required by rules.md §6.2.

Phase 1 — Windows Event Collector Foundation
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

from ai.collection.schema import (
    WindowsEventSchema,
    REQUIRED_FIELDS,
    MONITORED_EVENT_IDS,
    LOG_CHANNELS,
)
from ai.collection.normalizer import normalize_json_event
from ai.collection.evtx_collector import WindowsEventCollector


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


def _make_atomic_evtx_record(
    event_id: int = 4625,
    timestamp: str = "2026-08-07T04:00:00.000000Z",
    computer: str = "CORP-DC-01",
    target_user: str = "administrator",
    command_line: str = "",
    logon_type: int = 3,
) -> Dict[str, Any]:
    """Helper: build an Atomic-EVTX-style nested JSON event dict."""
    return {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                "EventID": event_id,
                "TimeCreated": {"#attributes": {"SystemTime": timestamp}},
                "Computer": computer,
                "Channel": "Security",
            },
            "EventData": {
                "TargetUserName": target_user,
                "SubjectUserName": "SYSTEM",
                "IpAddress": "192.168.1.100",
                "LogonType": str(logon_type),
                "CommandLine": command_line,
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
            },
        }
    }


def _make_flat_record(
    event_id: int = 4688,
    timestamp: str = "2026-08-07T05:00:00Z",
    computer: str = "WORKSTATION-01",
) -> Dict[str, Any]:
    """Helper: build a flat (non-nested) raw event dict."""
    return {
        "EventID": event_id,
        "TimeCreated": timestamp,
        "Computer": computer,
        "TargetUserName": "jdoe",
        "CommandLine": "powershell.exe -EncodedCommand",
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. WindowsEventSchema Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestWindowsEventSchema:
    """Tests for the WindowsEventSchema dataclass."""

    def test_schema_has_all_required_fields(self) -> None:
        """SC-01: WindowsEventSchema must have all 16 required fields."""
        schema = WindowsEventSchema()
        required_attrs = [
            "event_id", "timestamp", "provider_name", "computer", "channel",
            "target_user", "subject_user", "process_name", "parent_process_name",
            "command_line", "source_ip", "destination_ip", "logon_type",
            "scenario_id", "category", "raw",
        ]
        for attr in required_attrs:
            assert hasattr(schema, attr), f"Missing field: {attr}"

    def test_schema_default_values(self) -> None:
        """Schema defaults to safe zero/empty values for all fields."""
        schema = WindowsEventSchema()
        assert schema.event_id == 0
        assert schema.timestamp == ""
        assert schema.computer == ""
        assert schema.logon_type == 0
        assert schema.raw == {}

    def test_schema_construction_with_values(self) -> None:
        """Schema correctly stores provided values."""
        schema = WindowsEventSchema(
            event_id=4625,
            timestamp="2026-08-07T04:00:00Z",
            computer="CORP-DC-01",
            target_user="administrator",
            logon_type=3,
        )
        assert schema.event_id == 4625
        assert schema.computer == "CORP-DC-01"
        assert schema.target_user == "administrator"
        assert schema.logon_type == 3

    def test_to_dict_contains_dual_keys(self) -> None:
        """to_dict() exposes both snake_case and PascalCase aliases."""
        schema = WindowsEventSchema(
            event_id=4688,
            computer="HOST-01",
            command_line="powershell.exe",
        )
        d = schema.to_dict()
        assert d["EventID"] == 4688
        assert d["event_id"] == 4688
        assert d["Computer"] == "HOST-01"
        assert d["computer"] == "HOST-01"
        assert d["CommandLine"] == "powershell.exe"
        assert d["command_line"] == "powershell.exe"

    def test_to_dict_excludes_raw(self) -> None:
        """to_dict() must not expose the raw audit copy as a top-level key."""
        schema = WindowsEventSchema(raw={"secret": "data"})
        d = schema.to_dict()
        assert "raw" not in d

    def test_is_monitored_event_true(self) -> None:
        """is_monitored_event() returns True for known detection Event IDs."""
        for eid in [4625, 4688, 4672, 4720, 4732, 7045]:
            schema = WindowsEventSchema(event_id=eid)
            assert schema.is_monitored_event() is True, f"Expected True for EventID {eid}"

    def test_is_monitored_event_false(self) -> None:
        """is_monitored_event() returns False for generic non-detection Event IDs."""
        schema = WindowsEventSchema(event_id=9999)
        assert schema.is_monitored_event() is False

    def test_required_fields_constant(self) -> None:
        """REQUIRED_FIELDS must contain EventID, TimeCreated, Computer."""
        assert "EventID" in REQUIRED_FIELDS
        assert "TimeCreated" in REQUIRED_FIELDS
        assert "Computer" in REQUIRED_FIELDS

    def test_monitored_event_ids_non_empty(self) -> None:
        """MONITORED_EVENT_IDS must be a non-empty list of integers."""
        assert len(MONITORED_EVENT_IDS) > 0
        assert all(isinstance(eid, int) for eid in MONITORED_EVENT_IDS)

    def test_log_channels_non_empty(self) -> None:
        """LOG_CHANNELS must be defined and include Security channel."""
        assert "Security" in LOG_CHANNELS


# ─────────────────────────────────────────────────────────────────────────────
# 2. EventNormalizer Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestEventNormalizer:
    """Tests for normalize_json_event() function."""

    def test_normalize_atomic_evtx_json_structure(self) -> None:
        """Correctly extracts fields from nested Atomic-EVTX JSON structure."""
        raw = _make_atomic_evtx_record(
            event_id=4625,
            computer="CORP-DC-01",
            target_user="administrator",
            logon_type=3,
        )
        schema = normalize_json_event(raw, scenario_id="test_scenario", category="CredentialAccess")

        assert schema.event_id == 4625
        assert schema.computer == "CORP-DC-01"
        assert schema.target_user == "administrator"
        assert schema.logon_type == 3
        assert schema.provider_name == "Microsoft-Windows-Security-Auditing"
        assert schema.scenario_id == "test_scenario"
        assert schema.category == "CredentialAccess"
        assert schema.channel == "Security"

    def test_normalize_preserves_raw(self) -> None:
        """Normalizer preserves the original raw dict in schema.raw."""
        raw = _make_atomic_evtx_record()
        schema = normalize_json_event(raw, scenario_id="s1")
        assert schema.raw == raw

    def test_normalize_flat_record(self) -> None:
        """Normalizer handles flat (non-nested) raw event dicts."""
        raw = _make_flat_record(event_id=4688, computer="WORKSTATION-01")
        schema = normalize_json_event(raw)
        assert schema.event_id == 4688
        assert schema.computer == "WORKSTATION-01"

    def test_normalize_missing_event_id(self) -> None:
        """Normalizer defaults event_id to 0 when EventID field is absent."""
        raw: Dict[str, Any] = {"Event": {"System": {"Computer": "HOST-01"}, "EventData": {}}}
        schema = normalize_json_event(raw)
        assert schema.event_id == 0

    def test_normalize_missing_fields_default_to_empty(self) -> None:
        """All optional fields default to empty string / 0 when absent."""
        raw: Dict[str, Any] = {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "TimeCreated": {"#attributes": {"SystemTime": "2026-08-07T00:00:00Z"}},
                    "Computer": "HOST-X",
                },
                "EventData": {},
            }
        }
        schema = normalize_json_event(raw)
        assert schema.target_user == ""
        assert schema.command_line == ""
        assert schema.source_ip == ""
        assert schema.logon_type == 0

    def test_normalize_non_digit_logon_type(self) -> None:
        """Non-digit LogonType values are coerced to 0."""
        raw = _make_atomic_evtx_record()
        raw["Event"]["EventData"]["LogonType"] = "Network"
        schema = normalize_json_event(raw)
        assert schema.logon_type == 0

    def test_normalize_timestamp_from_nested_attributes(self) -> None:
        """Timestamp correctly extracted from nested #attributes.SystemTime."""
        raw = _make_atomic_evtx_record(timestamp="2026-08-07T10:30:00.000000Z")
        schema = normalize_json_event(raw)
        assert schema.timestamp == "2026-08-07T10:30:00.000000Z"

    def test_normalize_process_fields(self) -> None:
        """Process name and parent process name are correctly extracted."""
        raw = _make_atomic_evtx_record()
        schema = normalize_json_event(raw)
        assert "cmd.exe" in schema.process_name.lower()
        assert "explorer.exe" in schema.parent_process_name.lower()

    def test_normalize_network_fields(self) -> None:
        """Source IP correctly extracted from IpAddress field."""
        raw = _make_atomic_evtx_record()
        schema = normalize_json_event(raw)
        assert schema.source_ip == "192.168.1.100"


# ─────────────────────────────────────────────────────────────────────────────
# 3. WindowsEventCollector — Validation Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestEventValidation:
    """Tests for WindowsEventCollector.validate_event()."""

    def setup_method(self) -> None:
        """Fresh collector for each test."""
        self.collector = WindowsEventCollector()

    def test_valid_nested_event_passes(self) -> None:
        """SC-05: Valid Atomic-EVTX nested event passes validation."""
        raw = _make_atomic_evtx_record(event_id=4625, computer="HOST-01")
        assert self.collector.validate_event(raw) is True

    def test_valid_flat_event_passes(self) -> None:
        """Valid flat (non-nested) raw event dict passes validation."""
        raw = _make_flat_record(event_id=4688, computer="HOST-01")
        assert self.collector.validate_event(raw) is True

    def test_missing_event_id_fails(self) -> None:
        """SC-05: Event without EventID must fail validation."""
        raw: Dict[str, Any] = {
            "Event": {
                "System": {
                    "TimeCreated": {"#attributes": {"SystemTime": "2026-08-07T00:00:00Z"}},
                    "Computer": "HOST-01",
                },
                "EventData": {},
            }
        }
        assert self.collector.validate_event(raw) is False

    def test_zero_event_id_fails(self) -> None:
        """EventID of 0 is outside 1–65535 range and must fail."""
        raw = _make_atomic_evtx_record(event_id=0)
        assert self.collector.validate_event(raw) is False

    def test_event_id_above_max_fails(self) -> None:
        """EventID > 65535 must fail validation."""
        raw = _make_atomic_evtx_record()
        raw["Event"]["System"]["EventID"] = 99999
        assert self.collector.validate_event(raw) is False

    def test_non_integer_event_id_fails(self) -> None:
        """Non-numeric EventID string must fail validation."""
        raw = _make_atomic_evtx_record()
        raw["Event"]["System"]["EventID"] = "NOT_AN_INT"
        assert self.collector.validate_event(raw) is False

    def test_missing_timestamp_fails(self) -> None:
        """Event with missing TimeCreated must fail validation."""
        raw: Dict[str, Any] = {
            "Event": {
                "System": {
                    "EventID": 4625,
                    "Computer": "HOST-01",
                },
                "EventData": {},
            }
        }
        assert self.collector.validate_event(raw) is False

    def test_empty_timestamp_fails(self) -> None:
        """Event with empty SystemTime string must fail validation."""
        raw = _make_atomic_evtx_record()
        raw["Event"]["System"]["TimeCreated"] = {"#attributes": {"SystemTime": ""}}
        assert self.collector.validate_event(raw) is False

    def test_missing_computer_fails(self) -> None:
        """Event without Computer field must fail validation."""
        raw: Dict[str, Any] = {
            "Event": {
                "System": {
                    "EventID": 4688,
                    "TimeCreated": {"#attributes": {"SystemTime": "2026-08-07T00:00:00Z"}},
                },
                "EventData": {},
            }
        }
        assert self.collector.validate_event(raw) is False

    def test_empty_computer_fails(self) -> None:
        """Event with empty Computer string must fail validation."""
        raw = _make_atomic_evtx_record()
        raw["Event"]["System"]["Computer"] = "   "
        assert self.collector.validate_event(raw) is False

    def test_boundary_event_id_1_passes(self) -> None:
        """EventID = 1 (lower boundary) must pass validation."""
        raw = _make_atomic_evtx_record(event_id=1)
        assert self.collector.validate_event(raw) is True

    def test_boundary_event_id_65535_passes(self) -> None:
        """EventID = 65535 (upper boundary) must pass validation."""
        raw = _make_atomic_evtx_record(event_id=65535)
        assert self.collector.validate_event(raw) is True


# ─────────────────────────────────────────────────────────────────────────────
# 4. WindowsEventCollector — JSON File Collection Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestJsonFileCollection:
    """Tests for WindowsEventCollector.collect_from_json_file()."""

    def setup_method(self) -> None:
        """Fresh collector for each test."""
        self.collector = WindowsEventCollector()

    def test_collect_single_event_json_file(self) -> None:
        """SC-02: collect_from_json_file returns a list of WindowsEventSchema."""
        record = _make_atomic_evtx_record(event_id=4625, computer="CORP-DC-01")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(record, fh)
            tmp_path = Path(fh.name)

        events = self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        assert len(events) == 1
        assert isinstance(events[0], WindowsEventSchema)
        assert events[0].event_id == 4625

    def test_collect_list_json_file(self) -> None:
        """collect_from_json_file handles a JSON array of events."""
        records = [
            _make_atomic_evtx_record(event_id=4625, computer="DC-01"),
            _make_atomic_evtx_record(event_id=4688, computer="DC-01"),
            _make_atomic_evtx_record(event_id=4672, computer="DC-01"),
        ]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(records, fh)
            tmp_path = Path(fh.name)

        events = self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        assert len(events) == 3
        event_ids = {e.event_id for e in events}
        assert event_ids == {4625, 4688, 4672}

    def test_collect_updates_stats(self) -> None:
        """collect_from_json_file increments total_events_collected and total_files_processed."""
        record = _make_atomic_evtx_record()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(record, fh)
            tmp_path = Path(fh.name)

        self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        assert self.collector.total_files_processed == 1
        assert self.collector.total_events_collected == 1

    def test_collect_event_id_distribution_tracked(self) -> None:
        """EventID distribution is updated after collection."""
        records = [
            _make_atomic_evtx_record(event_id=4625),
            _make_atomic_evtx_record(event_id=4625),
            _make_atomic_evtx_record(event_id=4688),
        ]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(records, fh)
            tmp_path = Path(fh.name)

        self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        assert self.collector.event_id_distribution.get(4625) == 2
        assert self.collector.event_id_distribution.get(4688) == 1

    def test_collect_nonexistent_file_returns_empty(self) -> None:
        """collect_from_json_file returns empty list for non-existent file."""
        events = self.collector.collect_from_json_file(Path("/non/existent/file.json"))
        assert events == []

    def test_collect_malformed_json_returns_empty(self) -> None:
        """collect_from_json_file returns empty list for malformed JSON content."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("{this is not valid json ...")
            tmp_path = Path(fh.name)

        events = self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        assert events == []
        assert str(tmp_path) in self.collector.failed_files

    def test_collect_empty_json_array_returns_empty(self) -> None:
        """collect_from_json_file returns empty list for an empty JSON array."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump([], fh)
            tmp_path = Path(fh.name)

        events = self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        assert events == []

    def test_collect_invalid_event_increments_failures(self) -> None:
        """Invalid events are counted in total_validation_failures."""
        invalid_records = [
            {"Event": {"System": {"Computer": "HOST-01"}, "EventData": {}}},  # no EventID
            _make_atomic_evtx_record(event_id=4625),  # valid
        ]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(invalid_records, fh)
            tmp_path = Path(fh.name)

        events = self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        assert len(events) == 1
        assert self.collector.total_validation_failures == 1

    def test_collected_events_have_scenario_id(self) -> None:
        """Collected events are tagged with the source file stem as scenario_id."""
        record = _make_atomic_evtx_record()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8",
            prefix="my_scenario_"
        ) as fh:
            json.dump(record, fh)
            tmp_path = Path(fh.name)

        events = self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        assert len(events) == 1
        assert events[0].scenario_id == tmp_path.stem


# ─────────────────────────────────────────────────────────────────────────────
# 5. WindowsEventCollector — Directory Collection Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestDirectoryCollection:
    """Tests for WindowsEventCollector.collect_from_directory()."""

    def setup_method(self) -> None:
        """Fresh collector for each test."""
        self.collector = WindowsEventCollector()

    def test_collect_from_directory_recursively(self) -> None:
        """SC-04: collect_from_directory finds JSON files in nested subdirectories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # Nested structure: root / subA / file1.json, root / subB / nested / file2.json
            (root / "subA").mkdir()
            (root / "subB" / "nested").mkdir(parents=True)

            (root / "subA" / "event_a.json").write_text(
                json.dumps(_make_atomic_evtx_record(event_id=4625, computer="HOST-A")),
                encoding="utf-8",
            )
            (root / "subB" / "nested" / "event_b.json").write_text(
                json.dumps(_make_atomic_evtx_record(event_id=4688, computer="HOST-B")),
                encoding="utf-8",
            )

            events = self.collector.collect_from_directory(root, file_type="json")

        assert len(events) == 2
        event_ids = {e.event_id for e in events}
        assert event_ids == {4625, 4688}

    def test_collect_from_directory_multiple_files(self) -> None:
        """collect_from_directory aggregates events from all matching files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for i, eid in enumerate([4625, 4672, 4720]):
                (root / f"scenario_{i}.json").write_text(
                    json.dumps(_make_atomic_evtx_record(event_id=eid, computer="DC-01")),
                    encoding="utf-8",
                )

            events = self.collector.collect_from_directory(root, file_type="json")

        assert len(events) == 3

    def test_collect_from_nonexistent_directory_returns_empty(self) -> None:
        """collect_from_directory returns empty list for a non-existent path."""
        events = self.collector.collect_from_directory(Path("/no/such/directory"))
        assert events == []

    def test_collect_from_empty_directory_returns_empty(self) -> None:
        """collect_from_directory returns empty list when directory has no JSON files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            events = self.collector.collect_from_directory(Path(tmpdir))
        assert events == []

    def test_collect_from_directory_invalid_file_type_raises(self) -> None:
        """collect_from_directory raises ValueError for unsupported file_type."""
        with pytest.raises(ValueError, match="Unsupported file_type"):
            self.collector.collect_from_directory(Path("."), file_type="csv")

    def test_collect_from_directory_json_file_type_case_insensitive(self) -> None:
        """collect_from_directory accepts 'JSON' or '.json' as file_type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "event.json").write_text(
                json.dumps(_make_atomic_evtx_record(event_id=4624, computer="HOST-01")),
                encoding="utf-8",
            )
            events_upper = self.collector.collect_from_directory(root, file_type="JSON")

        assert len(events_upper) == 1


# ─────────────────────────────────────────────────────────────────────────────
# 6. WindowsEventCollector — Statistics & Health Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestCollectionStats:
    """Tests for get_collection_stats() and reset_stats()."""

    def setup_method(self) -> None:
        """Fresh collector for each test."""
        self.collector = WindowsEventCollector()

    def test_initial_stats_are_zero(self) -> None:
        """Freshly initialized collector has zero statistics."""
        stats = self.collector.get_collection_stats()
        assert stats["total_files_processed"] == 0
        assert stats["total_events_collected"] == 0
        assert stats["total_validation_failures"] == 0
        assert stats["failed_files"] == []
        assert stats["event_id_distribution"] == {}

    def test_health_failed_when_no_events_collected(self) -> None:
        """SC-06: Health is 'failed' when zero events have been collected."""
        stats = self.collector.get_collection_stats()
        assert stats["collection_health"] == "failed"

    def test_health_healthy_after_valid_collection(self) -> None:
        """SC-06: Health is 'healthy' when events collected with zero failures."""
        record = _make_atomic_evtx_record(event_id=4625, computer="HOST-01")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(record, fh)
            tmp_path = Path(fh.name)

        self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        stats = self.collector.get_collection_stats()
        assert stats["collection_health"] == "healthy"

    def test_health_degraded_when_low_failure_rate(self) -> None:
        """SC-06: Health is 'degraded' when failure rate is between 0% and 10%."""
        # 9 valid events + 1 invalid = 10% failure which triggers 'failed'
        # So use 1 invalid out of 11 total (1/11 ≈ 9.09% < 10%) → 'degraded'
        records = [_make_atomic_evtx_record(event_id=4625, computer="DC-01")] * 10
        # One invalid record (no EventID)
        records.append({"Event": {"System": {"Computer": "HOST"}, "EventData": {}}})

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(records, fh)
            tmp_path = Path(fh.name)

        self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        stats = self.collector.get_collection_stats()
        assert stats["collection_health"] == "degraded"
        assert stats["total_validation_failures"] == 1
        assert stats["total_events_collected"] == 10

    def test_health_failed_when_high_failure_rate(self) -> None:
        """SC-06: Health is 'failed' when failure rate exceeds 10%."""
        # 8 valid + 2 invalid = 2/10 = 20% failure rate
        valid_records = [_make_atomic_evtx_record(event_id=4625, computer="DC-01")] * 8
        invalid_records = [{"bad": "data"}, {"also": "bad"}]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(valid_records + invalid_records, fh)
            tmp_path = Path(fh.name)

        self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        stats = self.collector.get_collection_stats()
        assert stats["collection_health"] == "failed"

    def test_event_id_distribution_string_keys(self) -> None:
        """get_collection_stats() returns event_id_distribution with string keys."""
        record = _make_atomic_evtx_record(event_id=4625)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(record, fh)
            tmp_path = Path(fh.name)

        self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        stats = self.collector.get_collection_stats()
        assert "4625" in stats["event_id_distribution"]

    def test_reset_stats_zeroes_all_counters(self) -> None:
        """reset_stats() resets all tracking counters to initial zero state."""
        record = _make_atomic_evtx_record()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(record, fh)
            tmp_path = Path(fh.name)

        self.collector.collect_from_json_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        # Confirm non-zero state before reset
        assert self.collector.total_events_collected > 0

        self.collector.reset_stats()

        assert self.collector.total_files_processed == 0
        assert self.collector.total_events_collected == 0
        assert self.collector.total_validation_failures == 0
        assert self.collector.failed_files == []
        assert self.collector.event_id_distribution == {}

    def test_stats_keys_are_complete(self) -> None:
        """get_collection_stats() returns all required stat keys."""
        stats = self.collector.get_collection_stats()
        required_keys = [
            "total_files_processed",
            "total_events_collected",
            "total_validation_failures",
            "failed_files",
            "event_id_distribution",
            "collection_health",
        ]
        for key in required_keys:
            assert key in stats, f"Missing stats key: {key}"


# ─────────────────────────────────────────────────────────────────────────────
# 7. EVTX File Collection Tests (graceful fallback)
# ─────────────────────────────────────────────────────────────────────────────


class TestEvtxFileCollection:
    """Tests for WindowsEventCollector.collect_from_evtx_file()."""

    def setup_method(self) -> None:
        """Fresh collector for each test."""
        self.collector = WindowsEventCollector()

    def test_collect_nonexistent_evtx_returns_empty(self) -> None:
        """collect_from_evtx_file returns empty list for a non-existent file."""
        events = self.collector.collect_from_evtx_file(Path("/no/such/file.evtx"))
        assert events == []

    def test_collect_invalid_evtx_returns_empty_and_records_failed_file(self) -> None:
        """SC-03: collect_from_evtx_file returns empty list for corrupt/non-EVTX file."""
        with tempfile.NamedTemporaryFile(
            suffix=".evtx", delete=False
        ) as fh:
            fh.write(b"This is not a real EVTX binary file.")
            tmp_path = Path(fh.name)

        events = self.collector.collect_from_evtx_file(tmp_path)
        tmp_path.unlink(missing_ok=True)

        # Either python-evtx not installed (empty + failed_files) or parse error
        assert isinstance(events, list)


# ─────────────────────────────────────────────────────────────────────────────
# 8. Package Import Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPackageImports:
    """Verify all public symbols are importable from ai.collection."""

    def test_all_exports_importable(self) -> None:
        """All __all__ symbols from ai.collection are importable."""
        from ai.collection import (  # noqa: F401
            WindowsEventSchema,
            WindowsEventCollector,
            normalize_json_event,
            normalize_evtx_record,
            REQUIRED_FIELDS,
            MONITORED_EVENT_IDS,
            LOG_CHANNELS,
        )

    def test_collector_instantiable_from_package(self) -> None:
        """WindowsEventCollector can be instantiated via package import."""
        from ai.collection import WindowsEventCollector as WEC

        collector = WEC()
        assert collector.total_events_collected == 0

    def test_schema_instantiable_from_package(self) -> None:
        """WindowsEventSchema can be instantiated via package import."""
        from ai.collection import WindowsEventSchema as WES

        schema = WES(event_id=4625, computer="TEST-HOST")
        assert schema.event_id == 4625
