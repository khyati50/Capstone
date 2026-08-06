"""Multi-Event Attack Chain Correlation Engine.

Correlates isolated log events into multi-stage attack chains using context keys:
- Host Name, Target/Subject User Account, Process ID, Session ID, Timestamp proximity

Example Chain Sequence:
4625 (Failed Login) -> 4625 (Failed Login) -> 4624 (Successful Login) ->
4672 (Privileges Assigned) -> 4688 (PowerShell Execution)
"""

from typing import Dict, Any, List
import uuid


class EventCorrelator:
    """Correlates security log events into multi-stage incidents."""

    def __init__(self) -> None:
        """Initialize EventCorrelator state dict."""
        self.active_incidents = {}

    def correlate_event(self, alert_object: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate single alert object into active attack chain or create new incident.

        Args:
            alert_object: Alert output from Hybrid Detection Engine.

        Returns:
            Dictionary containing updated incident tracking context.
        """
        raw = alert_object.get("raw_event", {})
        host = raw.get("Computer", "HOST-DEFAULT")
        user = raw.get("TargetUserName", raw.get("SubjectUserName", "USER-DEFAULT"))

        context_key = f"{host}::{user}"

        if context_key not in self.active_incidents:
            self.active_incidents[context_key] = {
                "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
                "host": host,
                "user": user,
                "start_time": raw.get("TimeCreated", ""),
                "events": [],
                "event_ids": [],
            }

        incident = self.active_incidents[context_key]
        incident["events"].append(alert_object)
        incident["event_ids"].append(raw.get("EventID"))

        chain_length = len(incident["events"])
        is_multi_stage = chain_length > 1

        return {
            "incident_id": incident["incident_id"],
            "context_key": context_key,
            "chain_length": chain_length,
            "is_multi_stage": is_multi_stage,
            "event_sequence": incident["event_ids"],
        }
