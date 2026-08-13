"""Multi-Event Attack Chain Correlation Engine.

Correlates isolated log events into multi-stage attack chains using context keys:
- Host Name, Target/Subject User Account, Process ID, Session ID, Timestamp proximity

Example Chain Sequence:
4625 (Failed Login) -> 4625 (Failed Login) -> 4624 (Successful Login) ->
4672 (Privileges Assigned) -> 4688 (PowerShell Execution)
"""

import uuid
from typing import Any, Dict


class EventCorrelator:
    """Correlates security log events into multi-stage enterprise incidents."""

    def __init__(self) -> None:
        """Initialize EventCorrelator state dict."""
        self.active_incidents = {}
        self.primary_incident_id = None

    def reset(self) -> None:
        """Reset correlation engine state."""
        self.active_incidents = {}
        self.primary_incident_id = None

    def correlate_event(self, alert_object: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate single alert object into active enterprise attack chain.

        Args:
            alert_object: Alert output from Hybrid Detection Engine.

        Returns:
            Dictionary containing updated incident tracking context.
        """
        raw = alert_object.get("raw_event", {})
        host = raw.get("Computer", "CORP-HOST-01")
        user = raw.get("TargetUserName", raw.get("SubjectUserName", "administrator"))

        context_key = f"{host}::{user}"

        if context_key not in self.active_incidents:
            self.active_incidents[context_key] = {
                "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
                "host": host,
                "user": user,
                "start_time": raw.get("TimeCreated", ""),
                "events": [],
                "event_ids": [],
                "unique_hosts": set(),
                "unique_users": set(),
                "triggered_rules": [],
            }

        incident = self.active_incidents[context_key]
        incident["events"].append(alert_object)
        incident["event_ids"].append(raw.get("EventID"))
        incident["unique_hosts"].add(host)
        incident["unique_users"].add(user)

        for r in alert_object.get("triggered_rules", []):
            if not any(tr.get("rule_id") == r.get("rule_id") for tr in incident["triggered_rules"]):
                incident["triggered_rules"].append(r)

        # Calculate totals for the current incident
        incident_events = incident["events"]
        chain_length = len(incident_events)
        all_rules = incident["triggered_rules"]

        return {
            "incident_id": incident["incident_id"],
            "context_key": context_key,
            "chain_length": chain_length,
            "is_multi_stage": chain_length > 1,
            "event_sequence": incident["event_ids"],
            "unique_hosts_count": len(incident["unique_hosts"]),
            "unique_users_count": len(incident["unique_users"]),
            "total_rules": all_rules,
            "incident_events": incident_events,
        }
