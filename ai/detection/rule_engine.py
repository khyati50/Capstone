"""Signature-Based Deterministic Rule Engine.

Evaluates security rules against event metadata:
- Brute Force: >5 Event 4625 failed logins in 5 minutes
- Privilege Escalation: Event 4672 / Sysmon Event 1 sensitive assignment
- Suspicious PowerShell: Event 4688 with encoded/obfuscated command execution
- Admin Account Creation: Event 4720 / Event 4732
"""

from typing import Dict, Any, List


class RuleEngine:
    """Evaluates signature rules against log events."""

    def __init__(self) -> None:
        """Initialize RuleEngine instance."""
        pass

    def evaluate_rules(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate deterministic security rules against event dict.

        Args:
            event: Event metadata dictionary.

        Returns:
            List of triggered rule dictionaries.
        """
        triggered = []

        event_id = int(event.get("EventID", 0))
        failed_count = float(event.get("failed_login_count_5m", 0))
        cmd = str(event.get("CommandLine", "")).lower()
        proc = str(event.get("ProcessName", "")).lower()

        # Rule 1: Brute Force Threshold
        if event_id == 4625 or failed_count >= 5:
            triggered.append({
                "rule_id": "RULE_BRUTE_FORCE_001",
                "rule_name": "Brute Force Failed Authentication Threshold",
                "severity": "High",
                "tactic": "Credential Access",
                "technique_id": "T1110",
                "description": f"Failed login burst detected ({failed_count} attempts within 5 minutes).",
            })

        # Rule 2: Suspicious PowerShell Execution
        if event_id == 4688 or "powershell" in proc or "powershell" in cmd:
            if any(term in cmd for term in ["-encodedcommand", "bypass", "downloadstring", "iex", "hidden"]):
                triggered.append({
                    "rule_id": "RULE_POWERSHELL_SUSPICIOUS_002",
                    "rule_name": "Suspicious Obfuscated PowerShell Execution",
                    "severity": "High",
                    "tactic": "Execution",
                    "technique_id": "T1059.001",
                    "description": "PowerShell executed with execution policy bypass or encoded payload.",
                })

        # Rule 3: Privilege Escalation
        if event_id == 4672:
            triggered.append({
                "rule_id": "RULE_PRIV_ESC_003",
                "rule_name": "Special Privileges Assigned To User",
                "severity": "Medium",
                "tactic": "Privilege Escalation",
                "technique_id": "T1078",
                "description": "Sensitive admin privileges assigned to active logon session.",
            })

        # Rule 4: New Local Account Created
        if event_id == 4720:
            triggered.append({
                "rule_id": "RULE_ACCOUNT_CREATION_004",
                "rule_name": "New Local User Account Created",
                "severity": "High",
                "tactic": "Persistence",
                "technique_id": "T1136.001",
                "description": "New local user account created.",
            })
        elif event_id == 4732:
            triggered.append({
                "rule_id": "RULE_GROUP_MEMBER_ADDED_005",
                "rule_name": "User Added to Privileged Local Group",
                "severity": "High",
                "tactic": "Privilege Escalation",
                "technique_id": "T1069.001",
                "description": "User added to local administrators security group.",
            })

        return triggered
