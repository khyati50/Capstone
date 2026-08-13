"""Centralized Configuration & Constants for Threat Detection System."""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_ROOT = BASE_DIR / "dataset" / "atomic-evtx-extracted" / "attacks_by_category_atomic_and_tools_removed"
ARTIFACTS_DIR = BASE_DIR / "ai" / "models" / "artifacts"

# Splitting Ratios
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

# Feature Lists
NUMERICAL_FEATURES = [
    "failed_login_count_5m",
    "time_delta_prev_event",
    "is_powershell_executed",
    "privilege_escalation_flag",
    "unusual_process_parent_ratio",
    "session_duration",
    "commandline_entropy",
    "event_frequency_1h",
    "is_known_attack_eventid",
    "process_name_entropy",
]

CATEGORICAL_FEATURES = [
    "EventID",
    "Provider_Name",
    "LogonType",
]

ALL_FEATURE_KEYS = NUMERICAL_FEATURES + CATEGORICAL_FEATURES

# Model Parameters
RANDOM_STATE = 42
FASTAPI_PORT = 8000
EXPRESS_PORT = 5000

# Item 10 & 11: Configurable Risk Engine Weights & Security Features Config
RISK_ENGINE_CONFIG = {
    "ai_confidence_max_points": 25.0,
    "rule_hits_max_points": 20.0,
    "mitre_tactic_max_points": 20.0,
    "tactic_diversity_max_points": 20.0,
    "scope_max_points": 15.0,
}

TACTIC_STAGE_SCORES = {
    "Initial Access": 4.0,
    "Credential Access": 6.0,
    "Execution": 9.0,
    "Defense Evasion": 10.0,
    "Discovery": 11.0,
    "Lateral Movement": 12.0,
    "Collection": 13.0,
    "Privilege Escalation": 14.0,
    "Persistence": 16.0,
    "Command and Control": 17.0,
    "Exfiltration": 19.0,
    "Impact": 20.0,
}

TACTIC_DIVERSITY_SCORES = {
    0: 0.0,
    1: 8.0,
    2: 14.0,
    3: 18.0,
}

EVENT_TO_TACTIC = {
    4625: "Credential Access",
    4688: "Execution",
    4672: "Privilege Escalation",
    7045: "Persistence",
    4720: "Persistence",
    4732: "Privilege Escalation",
    4624: "Initial Access",
}

CORROBORATION_MULTIPLIER = {
    "AI_AND_RULE_AGREEMENT": 1.15,
    "RULE_SIGNATURE_ONLY": 1.05,
    "AI_ANOMALY_ONLY": 1.00,
    "BENIGN": 0.00,
}

CRITICAL_EVENT_IDS = [4672, 4720, 4732, 7045]
HIGH_EVENT_IDS = [4625, 4688]
