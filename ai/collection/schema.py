"""Windows Event Schema — Canonical Internal Event Representation.

Defines the authoritative data structure for all Windows Security Event Log
records after collection and normalization from EVTX or JSON sources.

Phase 1 — Windows Event Collector Foundation
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

# Minimum required fields for a raw event to pass validation
REQUIRED_FIELDS: List[str] = ["EventID", "TimeCreated", "Computer"]

# Windows Security Event IDs monitored by the detection pipeline
MONITORED_EVENT_IDS: List[int] = [
    4624,  # An account was successfully logged on
    4625,  # An account failed to log on
    4634,  # An account was logged off
    4648,  # A logon was attempted using explicit credentials
    4672,  # Special privileges assigned to new logon (privilege escalation)
    4688,  # A new process has been created
    4697,  # A service was installed in the system
    4720,  # A user account was created
    4732,  # A member was added to a security-enabled local group
    4738,  # A user account was changed
    4756,  # A member was added to a security-enabled universal group
    7045,  # A new service was installed in the system
    1,  # Sysmon: Process Create
    3,  # Sysmon: Network Connection Detected
    11,  # Sysmon: FileCreate
]

# Log channels mapped to provider context
LOG_CHANNELS: List[str] = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Sysmon/Operational",
    "Windows PowerShell",
]


@dataclass
class WindowsEventSchema:
    """Canonical internal representation of a normalized Windows Security Event.

    All fields are extracted from raw EVTX binary or JSON log records and
    normalized to a consistent schema regardless of source format.

    Attributes:
        event_id: Windows Event ID integer (1–65535).
        timestamp: ISO 8601 UTC timestamp string from SystemTime.
        provider_name: Log provider name (e.g. Microsoft-Windows-Security-Auditing).
        computer: Hostname of the machine that generated the event.
        channel: Log channel the event was recorded in.
        target_user: Target username referenced in the event.
        subject_user: Subject (initiating) username.
        process_name: Full path of the executed process or image.
        parent_process_name: Full path of the parent process.
        command_line: Full command-line string used to launch the process.
        source_ip: Source IP address from network-related events.
        destination_ip: Destination IP address from network-related events.
        logon_type: Numeric logon type code (0 if not applicable).
        scenario_id: Source file stem used as scenario identifier.
        category: Attack category label derived from directory name.
        raw: Original unmodified raw event dictionary preserved for auditability.
    """

    event_id: int = 0
    timestamp: str = ""
    provider_name: str = ""
    computer: str = ""
    channel: str = ""
    target_user: str = ""
    subject_user: str = ""
    process_name: str = ""
    parent_process_name: str = ""
    command_line: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    logon_type: int = 0
    scenario_id: str = ""
    category: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize schema to a plain dictionary for downstream pipeline consumption.

        Returns:
            Dictionary containing all schema fields except the raw audit copy.
        """
        return {
            "event_id": self.event_id,
            "EventID": self.event_id,
            "timestamp": self.timestamp,
            "TimeCreated": self.timestamp,
            "provider_name": self.provider_name,
            "Provider_Name": self.provider_name,
            "computer": self.computer,
            "Computer": self.computer,
            "channel": self.channel,
            "target_user": self.target_user,
            "TargetUserName": self.target_user,
            "subject_user": self.subject_user,
            "SubjectUserName": self.subject_user,
            "process_name": self.process_name,
            "ProcessName": self.process_name,
            "parent_process_name": self.parent_process_name,
            "ParentProcessName": self.parent_process_name,
            "command_line": self.command_line,
            "CommandLine": self.command_line,
            "source_ip": self.source_ip,
            "SourceIp": self.source_ip,
            "destination_ip": self.destination_ip,
            "DestinationIp": self.destination_ip,
            "logon_type": self.logon_type,
            "LogonType": self.logon_type,
            "scenario_id": self.scenario_id,
            "category": self.category,
        }

    def is_monitored_event(self) -> bool:
        """Check whether this event's ID is in the monitored detection set.

        Returns:
            True if the event ID is in MONITORED_EVENT_IDS, False otherwise.
        """
        return self.event_id in MONITORED_EVENT_IDS
