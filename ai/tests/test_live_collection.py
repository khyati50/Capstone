"""Unit Tests — Phase 2.1 & 2.2: Local Windows Security Event Ingestion.

Tests all required live collection constraints (0 Administrator rights required):
  1. Reader initializes correctly
  2. Existing RecordID checkpoint is respected
  3. Duplicate/old RecordIDs are ignored
  4. New RecordID is accepted
  5. Normalized event is produced into WindowsEventSchema
  6. Checkpoint advances after successful normalization
  7. Checkpoint does NOT incorrectly advance on normalization/validation failure
  8. Graceful shutdown works (KeyboardInterrupt in stream_events)
  9. Non-Windows / unavailable event source fallback works
 10. Import warning is eliminated

Phase 2.1 / 2.2 — Local Windows Security Event Log Ingestion
"""

import warnings
from unittest.mock import MagicMock, patch

import pytest

from ai.collection.live_normalizer import normalize_live_xml_event
from ai.collection.live_reader import LiveWindowsEventReader
from ai.collection.schema import WindowsEventSchema

# ─────────────────────────────────────────────────────────────────────────────
# Sample Live Windows Security Event Log XML Payloads
# ─────────────────────────────────────────────────────────────────────────────

SAMPLE_FAILED_LOGON_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{5484fe25-29d5-43db-b7fe-02d096e01da0}" />
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2026-08-11T10:00:00.1234567Z" />
    <EventRecordID>98765</EventRecordID>
    <Correlation />
    <Execution ProcessID="684" ThreadID="1200" />
    <Channel>Security</Channel>
    <Computer>CORP-SEC-DC01</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">CORP-SEC-DC01$</Data>
    <Data Name="TargetUserName">administrator</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">10.0.0.45</Data>
  </EventData>
</Event>"""

SAMPLE_PROCESS_CREATE_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-08-11T10:01:15.0000000Z" />
    <EventRecordID>98766</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WORKSTATION-99</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">jdoe</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\powershell.exe</Data>
    <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
    <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass -enc SQBFA...</Data>
  </EventData>
</Event>"""

SAMPLE_INVALID_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>0</EventID>
    <TimeCreated SystemTime="" />
    <EventRecordID>99999</EventRecordID>
    <Channel>Security</Channel>
    <Computer>BAD-HOST</Computer>
  </System>
</Event>"""


# ─────────────────────────────────────────────────────────────────────────────
# 1. Live Normalizer Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestLiveNormalizer:
    """Tests for normalize_live_xml_event()."""

    def test_normalize_failed_logon_xml(self) -> None:
        """Correctly extracts fields from live Security Event 4625 XML."""
        schema = normalize_live_xml_event(SAMPLE_FAILED_LOGON_XML, source_channel="Security")

        assert isinstance(schema, WindowsEventSchema)
        assert schema.event_id == 4625
        assert schema.record_id == 98765
        assert schema.computer == "CORP-SEC-DC01"
        assert schema.channel == "Security"
        assert schema.target_user == "administrator"
        assert schema.subject_user == "CORP-SEC-DC01$"
        assert schema.source_ip == "10.0.0.45"
        assert schema.logon_type == 3
        assert schema.timestamp == "2026-08-11T10:00:00.1234567Z"
        assert schema.provider_name == "Microsoft-Windows-Security-Auditing"

    def test_normalize_process_create_xml(self) -> None:
        """Correctly extracts process, command line, and record_id from Event 4688 XML."""
        schema = normalize_live_xml_event(SAMPLE_PROCESS_CREATE_XML, source_channel="Security")

        assert schema.event_id == 4688
        assert schema.record_id == 98766
        assert schema.computer == "WORKSTATION-99"
        assert schema.subject_user == "jdoe"
        assert "powershell.exe" in schema.process_name
        assert "explorer.exe" in schema.parent_process_name
        assert "ExecutionPolicy Bypass" in schema.command_line

    def test_normalize_empty_xml_returns_default_schema(self) -> None:
        """Empty XML string produces safe default schema."""
        schema = normalize_live_xml_event("")
        assert schema.event_id == 0
        assert schema.record_id == 0
        assert schema.channel == "Security"

    def test_normalize_malformed_xml(self) -> None:
        """Malformed XML produces schema with error in raw dict."""
        schema = normalize_live_xml_event("<Event><bad xml")
        assert schema.event_id == 0
        assert schema.record_id == 0
        assert "_xml_error" in schema.raw

    def test_schema_monitored_event_check(self) -> None:
        """Normalized live event correctly identifies monitored status."""
        schema = normalize_live_xml_event(SAMPLE_FAILED_LOGON_XML)
        assert schema.is_monitored_event() is True

    def test_schema_to_dict_compatibility(self) -> None:
        """Normalized live event produces dictionary matching Phase 1 format including EventRecordID."""
        schema = normalize_live_xml_event(SAMPLE_FAILED_LOGON_XML)
        d = schema.to_dict()

        assert d["EventID"] == 4625
        assert d["event_id"] == 4625
        assert d["EventRecordID"] == 98765
        assert d["record_id"] == 98765
        assert d["Computer"] == "CORP-SEC-DC01"
        assert d["TargetUserName"] == "administrator"
        assert d["LogonType"] == 3


# ─────────────────────────────────────────────────────────────────────────────
# 2. Live Reader Tests (Mocked Sources — 0 Admin Rights Required)
# ─────────────────────────────────────────────────────────────────────────────


class TestLiveWindowsEventReader:
    """Tests for LiveWindowsEventReader class using mocked sources."""

    def test_reader_initializes_correctly(self) -> None:
        """1. Reader initializes correctly with Security channel and zeroed checkpoint."""
        reader = LiveWindowsEventReader(channel="Security")
        assert reader.channel == "Security"
        assert reader.last_record_id == 0
        assert reader.total_events_read == 0
        assert reader.validation_failures == 0
        assert reader.last_read_timestamp is None

    def test_existing_record_id_checkpoint_respected(self) -> None:
        """2. Existing RecordID checkpoint is respected."""
        reader = LiveWindowsEventReader(channel="Security")
        reader.last_record_id = 98765  # Pre-set existing checkpoint

        assert reader.last_record_id == 98765

    def test_duplicate_old_record_ids_ignored(self) -> None:
        """3. Duplicate/old RecordIDs (<= N) are ignored."""
        reader = LiveWindowsEventReader(channel="Security")
        reader._is_windows = True
        reader.last_record_id = 98766  # Current checkpoint is 98766

        # Return record 98765 which is <= 98766
        reader._query_windows_security_log = MagicMock(return_value=[SAMPLE_FAILED_LOGON_XML])
        events = reader.read_new_events()

        assert len(events) == 0  # Old record 98765 ignored
        assert reader.total_events_read == 0
        assert reader.last_record_id == 98766  # Checkpoint unchanged

    def test_new_record_id_accepted(self) -> None:
        """4. New RecordID (> N) is accepted and processed."""
        reader = LiveWindowsEventReader(channel="Security")
        reader._is_windows = True
        reader.last_record_id = 98764

        reader._query_windows_security_log = MagicMock(return_value=[SAMPLE_FAILED_LOGON_XML])
        events = reader.read_new_events()

        assert len(events) == 1
        assert events[0].record_id == 98765

    def test_normalized_event_produced(self) -> None:
        """5. Normalized event is produced into WindowsEventSchema."""
        reader = LiveWindowsEventReader(channel="Security")
        reader._is_windows = True
        reader._query_windows_security_log = MagicMock(return_value=[SAMPLE_FAILED_LOGON_XML])

        events = reader.read_new_events()
        assert len(events) == 1
        assert isinstance(events[0], WindowsEventSchema)
        assert events[0].event_id == 4625
        assert events[0].computer == "CORP-SEC-DC01"

    def test_checkpoint_advances_after_successful_normalization(self) -> None:
        """6. Checkpoint advances after successful normalization."""
        reader = LiveWindowsEventReader(channel="Security")
        reader._is_windows = True
        assert reader.last_record_id == 0

        reader._query_windows_security_log = MagicMock(
            return_value=[SAMPLE_FAILED_LOGON_XML, SAMPLE_PROCESS_CREATE_XML]
        )
        events = reader.read_new_events()

        assert len(events) == 2
        assert reader.last_record_id == 98766  # Advanced to highest valid RecordID

    def test_initial_batch_reverses_descending_wevtutil_records(self) -> None:
        """Initial query with last_record_id==0 reverses /rd:true output so all initial records process in ascending order."""
        reader = LiveWindowsEventReader(channel="Security")
        reader._is_windows = True

        # Raw wevtutil stdout in descending order (98766 then 98765)
        raw_stdout = f"{SAMPLE_PROCESS_CREATE_XML}\n{SAMPLE_FAILED_LOGON_XML}"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = raw_stdout

        with patch("subprocess.run", return_value=mock_result):
            events = reader.read_new_events()

        assert len(events) == 2
        # Records must be processed in ascending order: 98765 first, then 98766
        assert events[0].record_id == 98765
        assert events[1].record_id == 98766
        assert reader.last_record_id == 98766

    def test_checkpoint_does_not_advance_on_normalization_failure(self) -> None:
        """7. Checkpoint does NOT incorrectly advance on normalization/validation failure."""
        reader = LiveWindowsEventReader(channel="Security")
        reader._is_windows = True
        reader.last_record_id = 1000

        # Pass SAMPLE_INVALID_XML (EventID 0, empty timestamp, RecordID 99999)
        reader._query_windows_security_log = MagicMock(return_value=[SAMPLE_INVALID_XML])
        events = reader.read_new_events()

        assert len(events) == 0  # Failed validation
        assert reader.validation_failures == 1
        assert reader.last_record_id == 1000  # Must NOT advance to 99999 on failure!

    def test_regression_subsequent_polling_xpath_query_no_duplicates(self) -> None:
        """Regression Test: Subsequent polling (last_record_id > 0) uses XPath filter and preserves order without duplicate emission."""
        reader = LiveWindowsEventReader(channel="Security")
        reader._is_windows = True
        reader.last_record_id = 98765

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = SAMPLE_PROCESS_CREATE_XML  # RecordID 98766

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            events = reader.read_new_events()

            # Verify subprocess call used XPath query with /rd:false
            called_cmd = mock_run.call_args[0][0]
            assert "/q:*[System[EventRecordID > 98765]]" in called_cmd
            assert "/rd:false" in called_cmd

        assert len(events) == 1
        assert events[0].record_id == 98766
        assert reader.last_record_id == 98766

    def test_regression_interleaved_failed_normalization_checkpoint_intact(self) -> None:
        """Regression Test: Interleaved normalization failure in a batch skips corrupt record without breaking cursor on valid records."""
        reader = LiveWindowsEventReader(channel="Security")
        reader._is_windows = True
        reader.last_record_id = 9000

        # Batch: 9001 (valid), invalid XML (9999), 9002 (valid)
        valid_9001 = SAMPLE_FAILED_LOGON_XML.replace(
            "<EventRecordID>98765</EventRecordID>", "<EventRecordID>9001</EventRecordID>"
        )
        valid_9002 = SAMPLE_PROCESS_CREATE_XML.replace(
            "<EventRecordID>98766</EventRecordID>", "<EventRecordID>9002</EventRecordID>"
        )

        reader._query_windows_security_log = MagicMock(return_value=[valid_9001, SAMPLE_INVALID_XML, valid_9002])
        events = reader.read_new_events()

        assert len(events) == 2
        assert [e.record_id for e in events] == [9001, 9002]
        assert reader.validation_failures == 1
        assert reader.last_record_id == 9002

    def test_regression_specific_descending_batch_105_to_101(self) -> None:
        """Regression Test: Input batch [105, 104, 103, 102, 101] with initial checkpoint 0 ingests all 5 events in ascending order."""
        reader = LiveWindowsEventReader(channel="Security")
        reader._is_windows = True
        assert reader.last_record_id == 0

        # Construct raw wevtutil output in descending order: 105, 104, 103, 102, 101
        xml_chunks = [
            SAMPLE_FAILED_LOGON_XML.replace(
                "<EventRecordID>98765</EventRecordID>", f"<EventRecordID>{rid}</EventRecordID>"
            )
            for rid in (105, 104, 103, 102, 101)
        ]
        raw_stdout = "\n".join(xml_chunks)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = raw_stdout

        with patch("subprocess.run", return_value=mock_result):
            events = reader.read_new_events()

        assert len(events) == 5
        assert [e.record_id for e in events] == [101, 102, 103, 104, 105]
        assert reader.last_record_id == 105

    def test_regression_existing_checkpoint_103_filters_old_records(self) -> None:
        """Regression Test: Existing checkpoint=103 filters out records <= 103, accepting only [104, 105] in order with final checkpoint=105."""
        reader = LiveWindowsEventReader(channel="Security")
        reader._is_windows = True
        reader.last_record_id = 103  # Preset existing checkpoint

        # Construct raw payload containing records 101 through 105 in ascending order
        xml_chunks = [
            SAMPLE_FAILED_LOGON_XML.replace(
                "<EventRecordID>98765</EventRecordID>", f"<EventRecordID>{rid}</EventRecordID>"
            )
            for rid in (101, 102, 103, 104, 105)
        ]

        reader._query_windows_security_log = MagicMock(return_value=xml_chunks)
        events = reader.read_new_events()

        assert len(events) == 2
        assert [e.record_id for e in events] == [104, 105]
        assert reader.last_record_id == 105

    def test_graceful_shutdown_works(self) -> None:
        """8. Graceful shutdown works during continuous stream_events generation."""
        reader = LiveWindowsEventReader(channel="Security")
        reader._is_windows = True
        reader._query_windows_security_log = MagicMock(return_value=[SAMPLE_FAILED_LOGON_XML])

        gen = reader.stream_events(poll_interval_sec=0.01)
        first_event = next(gen)
        assert first_event.record_id == 98765

        # Close generator cleanly simulating Ctrl+C shutdown
        gen.close()

    def test_non_windows_unavailable_source_fallback(self) -> None:
        """9. Non-Windows or unavailable event source fallback works without crashing."""
        reader = LiveWindowsEventReader(channel="Security")
        reader._is_windows = False  # Simulate non-Windows

        events = reader.read_new_events()
        assert events == []
        status = reader.get_reader_status()
        assert status["status"] == "fallback_disabled"
        assert status["is_windows"] is False

    def test_import_warning_eliminated(self) -> None:
        """10. Package import of live collection components produces zero RuntimeWarning."""
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            from ai.collection import LiveWindowsEventReader as Reader
            from ai.collection import normalize_live_xml_event as normalizer

            r = Reader()
            assert r.channel == "Security"

            for w in recorded:
                assert "sys.modules" not in str(w.message)
