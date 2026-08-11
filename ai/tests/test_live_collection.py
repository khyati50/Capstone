"""Unit Tests — Phase 2.1: Local Windows Security Event Ingestion.

Tests the live collection components:
  - normalize_live_xml_event on live XML Security event structures
  - LiveWindowsEventReader initialization, XML splitting, and fallback
  - Schema compatibility of live-acquired events with WindowsEventSchema

Phase 2.1 — Local Windows Security Event Log Ingestion
"""

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
        assert schema.computer == "CORP-SEC-DC01"
        assert schema.channel == "Security"
        assert schema.target_user == "administrator"
        assert schema.subject_user == "CORP-SEC-DC01$"
        assert schema.source_ip == "10.0.0.45"
        assert schema.logon_type == 3
        assert schema.timestamp == "2026-08-11T10:00:00.1234567Z"
        assert schema.provider_name == "Microsoft-Windows-Security-Auditing"

    def test_normalize_process_create_xml(self) -> None:
        """Correctly extracts process and command line fields from Event 4688 XML."""
        schema = normalize_live_xml_event(SAMPLE_PROCESS_CREATE_XML, source_channel="Security")

        assert schema.event_id == 4688
        assert schema.computer == "WORKSTATION-99"
        assert schema.subject_user == "jdoe"
        assert "powershell.exe" in schema.process_name
        assert "explorer.exe" in schema.parent_process_name
        assert "ExecutionPolicy Bypass" in schema.command_line

    def test_normalize_empty_xml_returns_default_schema(self) -> None:
        """Empty XML string produces safe default schema."""
        schema = normalize_live_xml_event("")
        assert schema.event_id == 0
        assert schema.channel == "Security"

    def test_normalize_malformed_xml(self) -> None:
        """Malformed XML produces schema with error in raw dict."""
        schema = normalize_live_xml_event("<Event><bad xml")
        assert schema.event_id == 0
        assert "_xml_error" in schema.raw

    def test_schema_monitored_event_check(self) -> None:
        """Normalized live event correct identifies monitored status."""
        schema = normalize_live_xml_event(SAMPLE_FAILED_LOGON_XML)
        assert schema.is_monitored_event() is True

    def test_schema_to_dict_compatibility(self) -> None:
        """Normalized live event produces dictionary matching Phase 1 format."""
        schema = normalize_live_xml_event(SAMPLE_FAILED_LOGON_XML)
        d = schema.to_dict()

        assert d["EventID"] == 4625
        assert d["event_id"] == 4625
        assert d["Computer"] == "CORP-SEC-DC01"
        assert d["TargetUserName"] == "administrator"
        assert d["LogonType"] == 3


# ─────────────────────────────────────────────────────────────────────────────
# 2. Live Reader Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestLiveWindowsEventReader:
    """Tests for LiveWindowsEventReader class."""

    def test_reader_initialization(self) -> None:
        """Reader initializes with default Security channel."""
        reader = LiveWindowsEventReader(channel="Security")
        assert reader.channel == "Security"
        assert reader.total_events_read == 0
        assert reader.validation_failures == 0
        assert reader.last_read_timestamp is None

    def test_reader_status(self) -> None:
        """get_reader_status returns valid dictionary."""
        reader = LiveWindowsEventReader()
        status = reader.get_reader_status()

        assert status["channel"] == "Security"
        assert "is_windows" in status
        assert status["total_events_read"] == 0
        assert "status" in status

    def test_split_xml_events(self) -> None:
        """_split_xml_events splits multiple Event XML blocks."""
        combined_xml = f"{SAMPLE_FAILED_LOGON_XML}\n{SAMPLE_PROCESS_CREATE_XML}"
        reader = LiveWindowsEventReader()

        chunks = reader._split_xml_events(combined_xml)
        assert len(chunks) == 2
        assert "<EventID>4625</EventID>" in chunks[0]
        assert "<EventID>4688</EventID>" in chunks[1]

    def test_split_xml_events_empty_input(self) -> None:
        """_split_xml_events handles empty input safely."""
        reader = LiveWindowsEventReader()
        assert reader._split_xml_events("") == []
        assert reader._split_xml_events("   ") == []

    def test_package_exports(self) -> None:
        """Live collection components are exportable from ai.collection."""
        from ai.collection import LiveWindowsEventReader as Reader
        from ai.collection import normalize_live_xml_event as normalizer

        r = Reader()
        assert r.channel == "Security"
        s = normalizer(SAMPLE_FAILED_LOGON_XML)
        assert s.event_id == 4625
