"""Live Windows Event XML Normalizer.

Stateless normalization module that parses XML records obtained directly from
the local Windows Security Event Log and maps them to the canonical
WindowsEventSchema dataclass.

Phase 2.1 — Windows Real-Time Local Security Event Ingestion
"""

import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict

from ai.collection.schema import WindowsEventSchema

logger = logging.getLogger("LiveEventNormalizer")

# Standard Windows Event Log XML namespace
_WIN_EVT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def normalize_live_xml_event(
    xml_str: str,
    source_channel: str = "Security",
) -> WindowsEventSchema:
    """Normalize a raw Windows Security Event Log XML record into WindowsEventSchema.

    Parses the standard Windows Event Log XML layout emitted by Windows
    Security Event Log API / query interface and extracts core event metadata.

    Args:
        xml_str: Raw XML string of a single Windows Event record.
        source_channel: Originating log channel (default: 'Security').

    Returns:
        Normalized WindowsEventSchema dataclass instance.
    """
    if not xml_str or not xml_str.strip():
        logger.warning("Empty XML string passed to normalize_live_xml_event.")
        return WindowsEventSchema(channel=source_channel, scenario_id="live_security_log")

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        logger.error(f"Failed to parse live event XML: {exc}")
        return WindowsEventSchema(
            channel=source_channel,
            scenario_id="live_security_log",
            raw={"_xml_error": str(exc), "_raw_xml": xml_str},
        )

    def _find_system(tag: str) -> str:
        """Helper to extract text from System sub-elements under XML namespace."""
        system_node = root.find(f"{{{_WIN_EVT_NS}}}System")
        if system_node is not None:
            elem = system_node.find(f"{{{_WIN_EVT_NS}}}{tag}")
            if elem is not None and elem.text:
                return elem.text.strip()
        # Fallback search without namespace prefix if namespace absent
        fallback_sys = root.find("System")
        if fallback_sys is not None:
            elem = fallback_sys.find(tag)
            if elem is not None and elem.text:
                return elem.text.strip()
        return ""

    def _get_system_attr(tag: str, attr: str) -> str:
        """Helper to extract an attribute from a System sub-element."""
        system_node = root.find(f"{{{_WIN_EVT_NS}}}System")
        if system_node is not None:
            elem = system_node.find(f"{{{_WIN_EVT_NS}}}{tag}")
            if elem is not None:
                return elem.get(attr, "")
        fallback_sys = root.find("System")
        if fallback_sys is not None:
            elem = fallback_sys.find(tag)
            if elem is not None:
                return elem.get(attr, "")
        return ""

    # Extract System block data
    raw_eid = _find_system("EventID")
    try:
        event_id = int(raw_eid) if raw_eid else 0
    except ValueError:
        event_id = 0

    timestamp = _get_system_attr("TimeCreated", "SystemTime")
    provider_name = _get_system_attr("Provider", "Name")
    computer = _find_system("Computer")
    channel = _find_system("Channel") or source_channel

    # Extract EventData block data into a flat dict
    data_map: Dict[str, str] = {}
    event_data = root.find(f"{{{_WIN_EVT_NS}}}EventData")
    if event_data is None:
        event_data = root.find("EventData")

    if event_data is not None:
        for node in event_data:
            name = node.get("Name", "")
            val = node.text or ""
            if name:
                data_map[name] = val.strip()

    # User fields
    target_user = data_map.get("TargetUserName", data_map.get("User", ""))
    subject_user = data_map.get("SubjectUserName", "")

    # Process fields
    process_name = data_map.get("NewProcessName", data_map.get("Image", ""))
    parent_process_name = data_map.get("ParentProcessName", data_map.get("ParentImage", ""))
    command_line = data_map.get("CommandLine", "")

    # Network fields
    source_ip = data_map.get("IpAddress", data_map.get("SourceIp", ""))
    destination_ip = data_map.get("DestinationIp", "")

    # LogonType
    logon_raw = data_map.get("LogonType", "0")
    logon_type = int(logon_raw) if logon_raw.isdigit() else 0

    # Extract EventRecordID (unique record identity in Windows Event Log)
    raw_rec_id = _find_system("EventRecordID")
    try:
        record_id = int(raw_rec_id) if raw_rec_id else 0
    except ValueError:
        record_id = 0

    raw_dict: Dict[str, Any] = {
        "event_id": event_id,
        "record_id": record_id,
        "timestamp": timestamp,
        "computer": computer,
        "_raw_xml": xml_str,
    }

    return WindowsEventSchema(
        event_id=event_id,
        timestamp=timestamp,
        provider_name=provider_name,
        computer=computer,
        channel=channel,
        target_user=target_user,
        subject_user=subject_user,
        process_name=process_name,
        parent_process_name=parent_process_name,
        command_line=command_line,
        source_ip=source_ip,
        destination_ip=destination_ip,
        logon_type=logon_type,
        scenario_id="live_security_log",
        category="local_security_event",
        record_id=record_id,
        raw=raw_dict,
    )
