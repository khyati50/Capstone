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
