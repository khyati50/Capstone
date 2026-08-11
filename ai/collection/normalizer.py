"""Event Normalizer — Maps Raw EVTX/JSON Structures to WindowsEventSchema.

Stateless normalization functions that extract fields from the raw Windows
Event Log record structures (both JSON and python-evtx binary formats) and
map them onto the canonical WindowsEventSchema dataclass.

Phase 1 — Windows Event Collector Foundation
"""

import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict

from ai.collection.schema import WindowsEventSchema

logger = logging.getLogger("EventNormalizer")

# XML namespace used in EVTX record elements
_EVTX_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def normalize_json_event(
    raw: Dict[str, Any],
    scenario_id: str = "",
    category: str = "",
) -> WindowsEventSchema:
    """Normalize a raw Atomic-EVTX JSON event dictionary to WindowsEventSchema.

    The Atomic-EVTX JSON files use nested structure:
      ``{ "Event": { "System": {...}, "EventData": {...} } }``

    Args:
        raw: Raw event dictionary as loaded from a JSON file.
        scenario_id: Source filename stem for traceability.
        category: Attack category label from directory hierarchy.

    Returns:
        Normalized WindowsEventSchema instance.
    """
    event_block = raw.get("Event", raw)
    system_block: Dict[str, Any] = event_block.get("System", {})
    event_data: Dict[str, Any] = event_block.get("EventData", {})

    # --- EventID ---
    raw_event_id = system_block.get("EventID", raw.get("EventID", 0))
    try:
        event_id = int(raw_event_id) if raw_event_id else 0
    except (ValueError, TypeError):
        event_id = 0

    # --- Timestamp ---
    time_attrs = system_block.get("TimeCreated", {})
    if isinstance(time_attrs, dict):
        timestamp = time_attrs.get("#attributes", {}).get("SystemTime", "")
    else:
        timestamp = str(time_attrs) if time_attrs else raw.get("TimeCreated", "")

    # --- Provider ---
    provider_block = system_block.get("Provider", {})
    if isinstance(provider_block, dict):
        provider_name = provider_block.get("#attributes", {}).get("Name", "")
    else:
        provider_name = str(provider_block) if provider_block else ""

    # --- Computer / Channel ---
    computer = str(system_block.get("Computer", raw.get("Computer", "")))
    channel = str(system_block.get("Channel", ""))

    # --- User fields ---
    target_user = str(event_data.get("TargetUserName", event_data.get("User", "")))
    subject_user = str(event_data.get("SubjectUserName", ""))

    # --- Process fields ---
    process_name = str(event_data.get("NewProcessName", event_data.get("Image", "")))
    parent_process_name = str(event_data.get("ParentProcessName", event_data.get("ParentImage", "")))
    command_line = str(event_data.get("CommandLine", ""))

    # --- Network fields ---
    source_ip = str(event_data.get("IpAddress", event_data.get("SourceIp", "")))
    destination_ip = str(event_data.get("DestinationIp", ""))

    # --- LogonType ---
    logon_raw = str(event_data.get("LogonType", "0"))
    logon_type = int(logon_raw) if logon_raw.isdigit() else 0

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
        scenario_id=scenario_id,
        category=category,
        raw=raw,
    )


def normalize_evtx_record(record: Any, scenario_id: str = "") -> WindowsEventSchema:
    """Normalize a python-evtx Evtx.Record to WindowsEventSchema.

    Parses the XML representation exposed by the python-evtx library and maps
    System / EventData elements to the canonical schema fields.

    Args:
        record: An ``Evtx.Record`` object from the python-evtx library.
        scenario_id: Source filename stem for traceability.

    Returns:
        Normalized WindowsEventSchema instance.
    """
    try:
        xml_str = record.xml()
        root = ET.fromstring(xml_str)
    except Exception as exc:
        logger.warning(f"Failed to parse EVTX record XML for scenario '{scenario_id}': {exc}")
        return WindowsEventSchema(scenario_id=scenario_id)

    def _find(element: ET.Element, tag: str) -> str:
        """Find first element matching tag in EVTX namespace and return text."""
        node = element.find(f"{{{_EVTX_NS}}}{tag}")
        return node.text.strip() if node is not None and node.text else ""

    def _attr(element: ET.Element, tag: str, attr_name: str) -> str:
        """Find element by tag and return a named attribute value."""
        node = element.find(f"{{{_EVTX_NS}}}{tag}")
        return node.get(attr_name, "") if node is not None else ""

    system = root.find(f"{{{_EVTX_NS}}}System")
    event_data = root.find(f"{{{_EVTX_NS}}}EventData")
    user_data = root.find(f"{{{_EVTX_NS}}}UserData")

    # Build a flat key-value dict from EventData <Data Name="..."> elements
    data_map: Dict[str, str] = {}
    data_container = event_data if event_data is not None else user_data
    if data_container is not None:
        for data_node in data_container:
            name = data_node.get("Name", "")
            value = data_node.text or ""
            if name:
                data_map[name] = value.strip()

    # EventID
    try:
        event_id = int(_find(system, "EventID")) if system is not None else 0
    except ValueError:
        event_id = 0

    # Timestamp
    timestamp = _attr(system, "TimeCreated", "SystemTime") if system is not None else ""

    # Provider
    provider_name = _attr(system, "Provider", "Name") if system is not None else ""

    # Computer / Channel
    computer = _find(system, "Computer") if system is not None else ""
    channel = _find(system, "Channel") if system is not None else ""

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

    raw_dict: Dict[str, Any] = {"_evtx_xml": xml_str, "scenario_id": scenario_id}

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
        scenario_id=scenario_id,
        category="",
        raw=raw_dict,
    )
