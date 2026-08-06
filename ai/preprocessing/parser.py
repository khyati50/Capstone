"""JSON Log Parser for Atomic-EVTX Windows & Sysmon Log Files.

Parses raw EVTX JSON logs and extracts core security event metadata:
- TimeCreated, EventID, Provider_Name, Computer
- TargetUserName, SubjectUserName, ProcessName, ParentProcessName
- CommandLine, SourceIp, DestinationIp, LogonType
"""

import json
from pathlib import Path
from typing import Any, Dict, List
import pandas as pd


def parse_scenario_json(json_path: Path) -> List[Dict[str, Any]]:
    """Parse a single Atomic-EVTX scenario JSON file.

    Args:
        json_path: Path to the JSON log file.

    Returns:
        List of parsed record dictionaries.
    """
    records = []
    if not json_path.exists():
        return records

    try:
        with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                event_data = item.get("Event", {}).get("EventData", {})
                system_data = item.get("Event", {}).get("System", {})

                record = {
                    "scenario_id": json_path.stem,
                    "category": json_path.parent.parent.name if json_path.parent.name == "json" else json_path.parent.name,
                    "TimeCreated": system_data.get("TimeCreated", {}).get("#attributes", {}).get("SystemTime", ""),
                    "EventID": int(system_data.get("EventID", 0)),
                    "Provider_Name": system_data.get("Provider", {}).get("#attributes", {}).get("Name", ""),
                    "Computer": system_data.get("Computer", ""),
                    "TargetUserName": event_data.get("TargetUserName", event_data.get("User", "")),
                    "SubjectUserName": event_data.get("SubjectUserName", ""),
                    "ProcessName": event_data.get("NewProcessName", event_data.get("Image", "")),
                    "ParentProcessName": event_data.get("ParentProcessName", event_data.get("ParentImage", "")),
                    "CommandLine": event_data.get("CommandLine", ""),
                    "SourceIp": event_data.get("IpAddress", event_data.get("SourceIp", "")),
                    "DestinationIp": event_data.get("DestinationIp", ""),
                    "LogonType": int(event_data.get("LogonType", 0)) if str(event_data.get("LogonType", "0")).isdigit() else 0,
                }
                records.append(record)
    except Exception:
        pass

    return records


def parse_all_scenarios(dataset_root: Path) -> pd.DataFrame:
    """Recursively parse all scenario JSON files in dataset_root.

    Args:
        dataset_root: Root directory containing category folders.

    Returns:
        DataFrame containing parsed log events.
    """
    all_records = []
    if not dataset_root.exists():
        return pd.DataFrame()

    json_files = list(dataset_root.rglob("*.json"))
    for json_file in json_files:
        records = parse_scenario_json(json_file)
        all_records.extend(records)

    if not all_records:
        return pd.DataFrame()

    df = pd.DataFrame(all_records)
    if "TimeCreated" in df.columns:
        df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], errors="coerce")
        df = df.sort_values("TimeCreated").reset_index(drop=True)
    return df
