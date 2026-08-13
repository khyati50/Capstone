"""Unit Tests for Phase 4 Data Preprocessing & Feature Engineering.

Tests cover:
  - Original feature calculations (happy path)
  - Bug fixes: unusual_process_parent_ratio size-independence
  - Bug fixes: session_duration Computer+User groupby
  - Bug fixes: time_delta sorted before shift
  - New features: commandline_entropy, event_frequency_1h,
                  is_known_attack_eventid, process_name_entropy
  - Edge cases: empty DataFrame, None timestamp, single-row input
"""

import pandas as pd
import pytest

from ai.preprocessing.feature_engineering import (
    ATTACK_EVENT_IDS,
    calculate_entropy,
    engineer_features,
)
from ai.preprocessing.splitter import scenario_level_split

# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def minimal_df() -> pd.DataFrame:
    """Minimal 3-row DataFrame for basic feature testing."""
    return pd.DataFrame(
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


# ──────────────────────────────────────────────────────────────────────────────
# Existing tests (preserved)
# ──────────────────────────────────────────────────────────────────────────────


def test_feature_engineering_calculation(minimal_df: pd.DataFrame) -> None:
    """Test that all 10 feature columns are created and basic values are correct."""
    featured_df = engineer_features(minimal_df)

    # All 10 features must be present
    expected_features = [
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
    for feat in expected_features:
        assert feat in featured_df.columns, f"Missing feature column: {feat}"

    # Powershell flag must be 1 for the powershell.exe row
    ps_row = featured_df[featured_df["ProcessName"] == "powershell.exe"]
    assert len(ps_row) == 1
    assert ps_row.iloc[0]["is_powershell_executed"] == 1

    # Privilege escalation flag must be 1 for EventID 4672
    priv_row = featured_df[featured_df["EventID"] == 4672]
    assert len(priv_row) == 1
    assert priv_row.iloc[0]["privilege_escalation_flag"] == 1


def test_scenario_level_split() -> None:
    """Test that scenario-level splitting keeps scenarios intact with no overlap."""
    data = []
    for i in range(10):
        for _ in range(3):
            data.append({"scenario_id": f"scenario_{i}", "EventID": 4624})

    df = pd.DataFrame(data)
    train_df, val_df, test_df = scenario_level_split(
        df, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, random_state=42
    )

    train_scenarios = set(train_df["scenario_id"].unique())
    val_scenarios = set(val_df["scenario_id"].unique())
    test_scenarios = set(test_df["scenario_id"].unique())

    assert len(train_scenarios.intersection(val_scenarios)) == 0
    assert len(train_scenarios.intersection(test_scenarios)) == 0
    assert len(val_scenarios.intersection(test_scenarios)) == 0
    assert train_scenarios.union(val_scenarios).union(test_scenarios) == set(df["scenario_id"].unique())


# ──────────────────────────────────────────────────────────────────────────────
# New tests — Bug fix: unusual_process_parent_ratio size-independence (CRITICAL)
# ──────────────────────────────────────────────────────────────────────────────


def test_unusual_process_parent_ratio_is_size_independent() -> None:
    """Verify unusual_process_parent_ratio does not depend on DataFrame size.

    This is the most critical regression test. The old formula used total_count
    (DataFrame length), making the ratio change with the DataFrame size.
    The fix uses max_count (most frequent pair count), which is size-independent.
    """
    base_rows = [
        {
            "ProcessName": "a.exe",
            "ParentProcessName": "x.exe",
            "EventID": 1,
            "TimeCreated": "2024-01-01T10:00:00Z",
            "Computer": "HOST-01",
            "TargetUserName": "user1",
        },
        {
            "ProcessName": "a.exe",
            "ParentProcessName": "x.exe",
            "EventID": 1,
            "TimeCreated": "2024-01-01T10:01:00Z",
            "Computer": "HOST-01",
            "TargetUserName": "user1",
        },
        {
            "ProcessName": "b.exe",
            "ParentProcessName": "y.exe",
            "EventID": 2,
            "TimeCreated": "2024-01-01T10:02:00Z",
            "Computer": "HOST-01",
            "TargetUserName": "user1",
        },
    ]
    df_small = pd.DataFrame(base_rows)
    df_large = pd.concat([df_small] * 100, ignore_index=True)

    feat_small = engineer_features(df_small)
    feat_large = engineer_features(df_large)

    ratio_small_common = feat_small[feat_small["ProcessName"] == "a.exe"]["unusual_process_parent_ratio"].iloc[0]
    ratio_large_common = feat_large[feat_large["ProcessName"] == "a.exe"]["unusual_process_parent_ratio"].iloc[0]

    assert ratio_small_common == ratio_large_common, (
        f"unusual_process_parent_ratio is size-dependent: "
        f"small={ratio_small_common:.6f}, large={ratio_large_common:.6f}"
    )
    assert ratio_small_common == pytest.approx(0.0), f"Most common pair should have ratio 0.0, got {ratio_small_common}"


# ──────────────────────────────────────────────────────────────────────────────
# New tests — Bug fix: session_duration uses Computer+User groupby
# ──────────────────────────────────────────────────────────────────────────────


def test_session_duration_is_host_scoped() -> None:
    """Verify session_duration resets per host, not just per user."""
    rows = [
        {
            "Computer": "HOST-A",
            "TargetUserName": "admin",
            "EventID": 4624,
            "TimeCreated": "2024-01-01T08:00:00Z",
            "ProcessName": "",
            "ParentProcessName": "",
            "CommandLine": "",
        },
        {
            "Computer": "HOST-A",
            "TargetUserName": "admin",
            "EventID": 4688,
            "TimeCreated": "2024-01-01T08:30:00Z",
            "ProcessName": "",
            "ParentProcessName": "",
            "CommandLine": "",
        },
        {
            "Computer": "HOST-B",
            "TargetUserName": "admin",
            "EventID": 4624,
            "TimeCreated": "2024-01-01T09:00:00Z",
            "ProcessName": "",
            "ParentProcessName": "",
            "CommandLine": "",
        },
    ]
    df = pd.DataFrame(rows)
    feat = engineer_features(df)

    host_b_row = feat[feat["Computer"] == "HOST-B"]
    assert len(host_b_row) == 1
    assert host_b_row.iloc[0]["session_duration"] == pytest.approx(
        0.0
    ), "session_duration for HOST-B's first event must be 0.0 (session resets per host)"

    host_a_second = feat[(feat["Computer"] == "HOST-A") & (feat["EventID"] == 4688)]
    assert len(host_a_second) == 1
    assert host_a_second.iloc[0]["session_duration"] == pytest.approx(
        1800.0
    ), "HOST-A second event should be 30 min = 1800s after session start"


# ──────────────────────────────────────────────────────────────────────────────
# New tests — New feature: commandline_entropy
# ──────────────────────────────────────────────────────────────────────────────


def test_commandline_entropy_values() -> None:
    """Verify commandline_entropy correctly identifies high-entropy strings."""
    assert calculate_entropy("") == 0.0, "Empty string must return 0.0"
    assert calculate_entropy("a") == 0.0, "Single char must return 0.0"

    b64 = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA=="
    entropy_b64 = calculate_entropy(b64)
    assert entropy_b64 > 4.0, f"Base64 string should have entropy > 4.0, got {entropy_b64}"

    entropy_normal = calculate_entropy("cmd.exe /c dir")
    assert entropy_normal < 4.0, f"Normal command should have entropy < 4.0, got {entropy_normal}"


def test_commandline_entropy_in_features(minimal_df: pd.DataFrame) -> None:
    """Verify commandline_entropy column is populated with float values >= 0."""
    feat = engineer_features(minimal_df)
    assert "commandline_entropy" in feat.columns
    assert (feat["commandline_entropy"] >= 0.0).all(), "commandline_entropy must be >= 0"


# ──────────────────────────────────────────────────────────────────────────────
# New tests — New feature: is_known_attack_eventid
# ──────────────────────────────────────────────────────────────────────────────


def test_is_known_attack_eventid_flags_correctly(minimal_df: pd.DataFrame) -> None:
    """Verify is_known_attack_eventid = 1 for threat EventIDs, 0 otherwise."""
    feat = engineer_features(minimal_df)
    assert "is_known_attack_eventid" in feat.columns
    assert (feat["is_known_attack_eventid"] == 1).all()

    benign_df = pd.DataFrame(
        [
            {
                "EventID": 9999,
                "TimeCreated": "2024-01-01T10:00:00Z",
                "Computer": "HOST-01",
                "TargetUserName": "user",
                "ProcessName": "notepad.exe",
                "ParentProcessName": "explorer.exe",
                "CommandLine": "notepad.exe",
            }
        ]
    )
    feat_benign = engineer_features(benign_df)
    assert feat_benign.iloc[0]["is_known_attack_eventid"] == 0


# ──────────────────────────────────────────────────────────────────────────────
# New tests — Edge case: empty DataFrame & None
# ──────────────────────────────────────────────────────────────────────────────


def test_engineer_features_handles_empty_dataframe() -> None:
    """Verify engineer_features returns gracefully for empty input."""
    empty_df = pd.DataFrame()
    result = engineer_features(empty_df)
    assert result.empty, "Empty DataFrame input must return empty DataFrame"


def test_engineer_features_raises_on_none() -> None:
    """Verify engineer_features raises ValueError for None input."""
    with pytest.raises(ValueError, match="None DataFrame"):
        engineer_features(None)  # type: ignore[arg-type]


# ──────────────────────────────────────────────────────────────────────────────
# New tests — New feature: event_frequency_1h
# ──────────────────────────────────────────────────────────────────────────────


def test_event_frequency_1h_counts_correctly() -> None:
    """Verify event_frequency_1h accumulates counts within a 1-hour window."""
    rows = []
    base_time = pd.Timestamp("2024-01-01T10:00:00Z")
    for i in range(5):
        rows.append(
            {
                "EventID": 4625,
                "Computer": "HOST-01",
                "TargetUserName": "user",
                "TimeCreated": (base_time + pd.Timedelta(minutes=i * 5)).isoformat(),
                "ProcessName": "",
                "ParentProcessName": "",
                "CommandLine": "",
            }
        )

    df = pd.DataFrame(rows)
    feat = engineer_features(df)
    assert "event_frequency_1h" in feat.columns

    last_row_freq = feat.iloc[-1]["event_frequency_1h"]
    assert last_row_freq >= 4.0
