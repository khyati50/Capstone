"""JSON Log Parser for Atomic-EVTX Windows & Sysmon Log Files.

Parses raw EVTX JSON logs and extracts core security event metadata:
- TimeCreated, EventID, Provider_Name, Computer
- TargetUserName, SubjectUserName, ProcessName, ParentProcessName
- CommandLine, SourceIp, DestinationIp, LogonType
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("EVTX_Parser")

LAST_PARSER_SUMMARY: Dict[str, Any] = {
    "total_files_found": 0,
    "successful_files": 0,
    "failed_files": 0,
    "total_records_parsed": 0,
    "error_details": []
}


def parse_scenario_json(json_path: Path) -> List[Dict[str, Any]]:
    """Parse a single Atomic-EVTX scenario JSON file with explicit error logging.

    Args:
        json_path: Path to the JSON log file.

    Returns:
        List of parsed record dictionaries.
    """
    records = []
    if not json_path.exists():
        logger.warning(f"File does not exist: {json_path}")
        return records

    try:
        with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                event_data = item.get("Event", {}).get("EventData", {})
                system_data = item.get("Event", {}).get("System", {})

                parent_name = json_path.parent.name
                category_name = json_path.parent.parent.name if parent_name == "json" else parent_name
                logon_val = str(event_data.get("LogonType", "0"))
                logon_type = int(logon_val) if logon_val.isdigit() else 0

                record = {
                    "scenario_id": json_path.stem,
                    "category": category_name,
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
                    "LogonType": logon_type,
                }
                records.append(record)
    except json.JSONDecodeError as exc:
        err_msg = f"Malformed JSON in {json_path.name}: {exc}"
        logger.error(err_msg)
        LAST_PARSER_SUMMARY["error_details"].append({"file": str(json_path), "error": str(exc), "type": "JSONDecodeError"})
    except Exception as exc:
        err_msg = f"Unexpected error parsing {json_path.name}: {exc}"
        logger.error(err_msg)
        LAST_PARSER_SUMMARY["error_details"].append({"file": str(json_path), "error": str(exc), "type": type(exc).__name__})

    return records


def parse_all_scenarios(dataset_root: Path) -> pd.DataFrame:
    """Recursively parse all scenario JSON files in dataset_root and build error statistics report.

    Args:
        dataset_root: Root directory containing category folders.

    Returns:
        DataFrame containing parsed log events.
    """
    global LAST_PARSER_SUMMARY
    LAST_PARSER_SUMMARY = {
        "total_files_found": 0,
        "successful_files": 0,
        "failed_files": 0,
        "total_records_parsed": 0,
        "error_details": []
    }

    all_records = []
    if not dataset_root.exists():
        logger.warning(f"Dataset root folder does not exist: {dataset_root}")
        return pd.DataFrame()

    json_files = list(dataset_root.rglob("*.json"))
    LAST_PARSER_SUMMARY["total_files_found"] = len(json_files)

    for json_file in json_files:
        records = parse_scenario_json(json_file)
        if records:
            all_records.extend(records)
            LAST_PARSER_SUMMARY["successful_files"] += 1
        else:
            LAST_PARSER_SUMMARY["failed_files"] += 1

    LAST_PARSER_SUMMARY["total_records_parsed"] = len(all_records)
    logger.info(
        f"Parsing Summary: {LAST_PARSER_SUMMARY['successful_files']}/{LAST_PARSER_SUMMARY['total_files_found']} files parsed successfully, "
        f"{LAST_PARSER_SUMMARY['total_records_parsed']} records extracted, {LAST_PARSER_SUMMARY['failed_files']} errors."
    )

    if not all_records:
        return pd.DataFrame()

    df = pd.DataFrame(all_records)
    if "TimeCreated" in df.columns:
        df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], errors="coerce")
        df = df.sort_values("TimeCreated").reset_index(drop=True)
    return df


def get_last_parser_summary() -> Dict[str, Any]:
    """Return error statistics and parser summary report dict."""
    return LAST_PARSER_SUMMARY

