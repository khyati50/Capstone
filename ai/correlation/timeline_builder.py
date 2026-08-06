"""Interactive Chronological Attack Timeline Builder."""

from typing import Dict, Any, List


class TimelineBuilder:
    """Constructs visual node-graph timeline structures for frontend rendering."""

    def __init__(self) -> None:
        """Initialize TimelineBuilder instance."""
        pass

    def build_timeline_nodes(self, incident_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Construct graph node objects for visual timeline representation.

        Args:
            incident_data: Correlated incident data dictionary.

        Returns:
            List of visual timeline node objects.
        """
        nodes = []
        events = incident_data.get("events", [])

        for idx, evt in enumerate(events):
            raw = evt.get("raw_event", {})
            event_id = raw.get("EventID", 0)

            node_label = f"Event {event_id}"
            if event_id == 4625:
                node_label = "Failed Login (4625)"
            elif event_id == 4624:
                node_label = "Successful Login (4624)"
            elif event_id == 4672:
                node_label = "Admin Privileges Assigned (4672)"
            elif event_id == 4688:
                node_label = "Process Launched (4688)"
            elif event_id in [4720, 4732]:
                node_label = "Account Escalation (4720/4732)"

            nodes.append({
                "step": idx + 1,
                "node_id": f"node_{idx+1}",
                "event_id": event_id,
                "label": node_label,
                "timestamp": raw.get("TimeCreated", ""),
                "severity": evt.get("severity", "Medium"),
                "confidence": evt.get("confidence", 0.8),
                "computer": raw.get("Computer", ""),
                "user": raw.get("TargetUserName", raw.get("SubjectUserName", "")),
                "process": raw.get("ProcessName", ""),
            })

        return nodes
