"""Standardized MITRE ATT&CK Framework Mapping Engine.

Maps Windows Event IDs, Rule triggers, and Process activity directly to MITRE ATT&CK:
- 4625 -> T1110 (Brute Force / Credential Access)
- 4688 + PowerShell -> T1059.001 (Command & Scripting / Execution)
- 4672 -> T1078 (Valid Accounts / Privilege Escalation)
- 7045 -> T1543.003 (Service Execution / Persistence)
- 4720 -> T1136.001 (Account Creation / Persistence)
"""

from typing import Dict, Any, List


class MitreMapper:
    """Maps events to MITRE ATT&CK Tactics and Techniques."""

    def __init__(self) -> None:
        """Initialize MitreMapper with static mapping dictionary."""
        self.mapping_table = {
            4625: {
                "tactic": "Credential Access",
                "technique_name": "Brute Force",
                "technique_id": "T1110",
            },
            4688: {
                "tactic": "Execution",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "technique_id": "T1059.001",
            },
            4672: {
                "tactic": "Privilege Escalation",
                "technique_name": "Valid Accounts",
                "technique_id": "T1078",
            },
            7045: {
                "tactic": "Persistence",
                "technique_name": "Create or Modify System Process: Windows Service",
                "technique_id": "T1543.003",
            },
            4720: {
                "tactic": "Persistence",
                "technique_name": "Create Account: Local Account",
                "technique_id": "T1136.001",
            },
            4732: {
                "tactic": "Privilege Escalation",
                "technique_name": "Permission Group Discovery / Local Groups",
                "technique_id": "T1069.001",
            },
        }

    def map_event_to_mitre(self, event_or_alert: Dict[str, Any]) -> List[Dict[str, str]]:
        """Map event or alert dictionary to MITRE ATT&CK techniques.

        Args:
            event_or_alert: Log event or alert object.

        Returns:
            List of mapped MITRE technique dictionaries.
        """
        mappings = []

        event_id = int(event_or_alert.get("event_id", event_or_alert.get("EventID", 0)))
        raw = event_or_alert.get("raw_event", event_or_alert)

        if event_id in self.mapping_table:
            mappings.append(self.mapping_table[event_id])

        # Check PowerShell execution
        cmd = str(raw.get("CommandLine", "")).lower()
        if "powershell" in cmd and not any(m["technique_id"] == "T1059.001" for m in mappings):
            mappings.append({
                "tactic": "Execution",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "technique_id": "T1059.001",
            })

        # Fallback default if unmapped
        if not mappings:
            mappings.append({
                "tactic": "Defense Evasion",
                "technique_name": "Unusual Log Activity Anomaly",
                "technique_id": "T1036",
            })

        return mappings
