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
        """Initialize MitreMapper with static mapping dictionary and active state dict."""
        self.active_techniques = {}
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

    def reset(self) -> None:
        """Reset active cumulative MITRE techniques state."""
        self.active_techniques = {}

    def map_event_to_mitre(self, event_or_alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map event or alert dictionary to MITRE ATT&CK techniques and update cumulative state.

        Args:
            event_or_alert: Log event or alert object.

        Returns:
            List of accumulated active MITRE technique dictionaries.
        """
        event_id = int(event_or_alert.get("event_id", event_or_alert.get("EventID", 0)))
        raw = event_or_alert.get("raw_event", event_or_alert)

        mapped_now = []

        # Event ID & process mapping
        if event_id in self.mapping_table:
            mapped_now.append(self.mapping_table[event_id])

        cmd = str(raw.get("CommandLine", "")).lower()
        if "powershell" in cmd and not any(m["technique_id"] == "T1059.001" for m in mapped_now):
            mapped_now.append({
                "tactic": "Execution",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "technique_id": "T1059.001",
            })

        # Item 9: Dynamic MITRE Mapping over correlated event chains
        event_chain = event_or_alert.get("event_sequence", [])
        if 4625 in event_chain and 4624 in event_chain and not any(m["technique_id"] == "T1078" for m in mapped_now):
            mapped_now.append({
                "tactic": "Initial Access",
                "technique_name": "Valid Accounts: Domain / Local Accounts",
                "technique_id": "T1078",
            })

        if not mapped_now:
            mapped_now.append({
                "tactic": "Defense Evasion",
                "technique_name": "Unusual Log Activity Anomaly",
                "technique_id": "T1036",
            })


        # Update cumulative active_techniques counter
        for tech in mapped_now:
            tid = tech["technique_id"]
            if tid not in self.active_techniques:
                self.active_techniques[tid] = {
                    "tactic": tech["tactic"],
                    "technique_name": tech["technique_name"],
                    "technique_id": tid,
                    "active_alerts": 0,
                    "level": "High"
                }
            self.active_techniques[tid]["active_alerts"] += 1
            if self.active_techniques[tid]["active_alerts"] >= 3:
                self.active_techniques[tid]["level"] = "Critical"

        return list(self.active_techniques.values())

