"""Unit Tests for Phase 4 Data Preprocessing & Feature Engineering."""

import pytest
import pandas as pd
import numpy as np

from ai.preprocessing.feature_engineering import engineer_features
from ai.preprocessing.splitter import scenario_level_split


def test_feature_engineering_calculation():
    """Test calculation of domain-informed features on sample data."""
    raw_data = pd.DataFrame(
        [
            {
                "scenario_id": "scen_1",
                "TimeCreated": "2026-08-06T10:00:00Z",
                "EventID": 4625,
                "Computer": "HOST-01",
                "TargetUserName": "userA",
                "ProcessName": "cmd.exe",
                "ParentProcessName": "explorer.exe",
                "CommandLine": "cmd.exe /c dir",
                "LogonType": 3,
            },
            {
                "scenario_id": "scen_1",
                "TimeCreated": "2026-08-06T10:02:00Z",
                "EventID": 4688,
                "Computer": "HOST-01",
                "TargetUserName": "userA",
                "ProcessName": "powershell.exe",
                "ParentProcessName": "cmd.exe",
                "CommandLine": "powershell -ExecutionPolicy Bypass",
                "LogonType": 3,
            },
            {
                "scenario_id": "scen_2",
                "TimeCreated": "2026-08-06T10:03:00Z",
                "EventID": 4672,
                "Computer": "HOST-02",
                "TargetUserName": "adminB",
                "ProcessName": "lsass.exe",
                "ParentProcessName": "wininit.exe",
                "CommandLine": "",
                "LogonType": 2,
            },
        ]
    )

    featured_df = engineer_features(raw_data)

    assert "failed_login_count_5m" in featured_df.columns
    assert "time_delta_prev_event" in featured_df.columns
    assert "is_powershell_executed" in featured_df.columns
    assert "privilege_escalation_flag" in featured_df.columns
    assert "unusual_process_parent_ratio" in featured_df.columns
    assert "session_duration" in featured_df.columns

    # Verify powershell execution flag for row index 1
    assert featured_df.loc[1, "is_powershell_executed"] == 1
    # Verify privilege escalation flag for row index 2 (EventID 4672)
    assert featured_df.loc[2, "privilege_escalation_flag"] == 1


def test_scenario_level_split():
    """Test that scenario-level splitting keeps scenarios intact."""
    data = []
    for i in range(10):
        for _ in range(3):
            data.append({"scenario_id": f"scenario_{i}", "EventID": 4624})

    df = pd.DataFrame(data)
    train_df, val_df, test_df = scenario_level_split(
        df, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, random_state=42
    )

    total_scenarios = set(df["scenario_id"].unique())
    train_scenarios = set(train_df["scenario_id"].unique())
    val_scenarios = set(val_df["scenario_id"].unique())
    test_scenarios = set(test_df["scenario_id"].unique())

    # Ensure no scenario overlaps between splits
    assert len(train_scenarios.intersection(val_scenarios)) == 0
    assert len(train_scenarios.intersection(test_scenarios)) == 0
    assert len(val_scenarios.intersection(test_scenarios)) == 0
    assert train_scenarios.union(val_scenarios).union(test_scenarios) == total_scenarios
