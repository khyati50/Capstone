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
    "ai_confidence_max_points": 30.0,
    "rule_hits_max_points": 20.0,
    "event_severity_max_points": 15.0,
    "chain_length_max_points": 20.0,
    "scope_max_points": 15.0,
}

CRITICAL_EVENT_IDS = [4672, 4720, 4732, 7045]
HIGH_EVENT_IDS = [4625, 4688]

