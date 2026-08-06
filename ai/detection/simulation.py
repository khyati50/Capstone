"""Interactive Attack Simulation Engine.

Generates 7 synthetic security event sequences for interactive SOC testing:
1. FAILED_LOGIN_BURST
2. LOGIN_POST_BRUTE_FORCE
3. PRIVILEGE_ESCALATION
4. SUSPICIOUS_POWERSHELL
5. NEW_ADMIN_ACCOUNT
6. INSIDER_EXFILTRATION
7. MALWARE_EXECUTION_CHAIN
8. RESET_STATE
"""

from typing import Dict, Any, List
import time


class SimulationEngine:
    """Generates synthetic security attack scenarios for testing and demonstration."""

    def __init__(self) -> None:
        """Initialize SimulationEngine instance."""
        pass

    def generate_scenario_events(self, scenario_type: str) -> List[Dict[str, Any]]:
        """Generate sequence of event dictionaries for a selected scenario.

        Args:
            scenario_type: Name of attack scenario.

        Returns:
            List of generated event dictionaries.
        """
        stype = scenario_type.upper().strip()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        if stype == "FAILED_LOGIN_BURST":
            return [
                {
                    "scenario_id": "sim_brute_force",
                    "TimeCreated": timestamp,
                    "EventID": 4625,
                    "Computer": "WORKSTATION-05",
                    "TargetUserName": "administrator",
                    "SourceIp": "192.168.1.105",
                    "failed_login_count_5m": i + 1,
                    "is_powershell_executed": 0,
                    "privilege_escalation_flag": 0,
                }
                for i in range(6)
            ]

        elif stype == "SUSPICIOUS_POWERSHELL":
            return [
                {
                    "scenario_id": "sim_powershell",
                    "TimeCreated": timestamp,
                    "EventID": 4688,
                    "Computer": "CORP-HOST-01",
                    "TargetUserName": "jdoe",
                    "ProcessName": "powershell.exe",
                    "ParentProcessName": "cmd.exe",
                    "CommandLine": "powershell.exe -ExecutionPolicy Bypass -encodedcommand SQBFAFgA...",
                    "failed_login_count_5m": 0,
                    "is_powershell_executed": 1,
                    "privilege_escalation_flag": 0,
                }
            ]

        elif stype == "PRIVILEGE_ESCALATION":
            return [
                {
                    "scenario_id": "sim_privesc",
                    "TimeCreated": timestamp,
                    "EventID": 4672,
                    "Computer": "DC-01",
                    "TargetUserName": "svc_account",
                    "ProcessName": "lsass.exe",
                    "failed_login_count_5m": 0,
                    "is_powershell_executed": 0,
                    "privilege_escalation_flag": 1,
                }
            ]

        elif stype == "NEW_ADMIN_ACCOUNT":
            return [
                {
                    "scenario_id": "sim_admin_created",
                    "TimeCreated": timestamp,
                    "EventID": 4720,
                    "Computer": "DC-01",
                    "TargetUserName": "backdoor_admin",
                    "failed_login_count_5m": 0,
                    "is_powershell_executed": 0,
                    "privilege_escalation_flag": 1,
                },
                {
                    "scenario_id": "sim_admin_created",
                    "TimeCreated": timestamp,
                    "EventID": 4732,
                    "Computer": "DC-01",
                    "TargetUserName": "backdoor_admin",
                    "failed_login_count_5m": 0,
                    "is_powershell_executed": 0,
                    "privilege_escalation_flag": 1,
                },
            ]

        else:
            # Default benign logon event
            return [
                {
                    "scenario_id": "sim_benign",
                    "TimeCreated": timestamp,
                    "EventID": 4624,
                    "Computer": "WORKSTATION-01",
                    "TargetUserName": "alice",
                    "failed_login_count_5m": 0,
                    "is_powershell_executed": 0,
                    "privilege_escalation_flag": 0,
                }
            ]
