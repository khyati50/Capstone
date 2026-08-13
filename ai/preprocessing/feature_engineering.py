"""Domain-Informed Security Feature Engineering Pipeline.

Calculates 10 behavioral threat detection features from parsed Windows event logs.
Features are designed to be computed once on the unified merged DataFrame before
any train/val/test splitting, ensuring consistent normalization baselines.

Feature list:
    1. failed_login_count_5m      — rolling failed-login count (EventID 4625) per 5 min
    2. time_delta_prev_event      — seconds since previous event on same host
    3. is_powershell_executed     — PowerShell/encoded payload indicator
    4. privilege_escalation_flag  — EventID 4672/4720/4732 indicator
    5. unusual_process_parent_ratio — how rare is this parent→child process pair
    6. session_duration           — elapsed time from first event per host+user session
    7. commandline_entropy        — Shannon entropy of CommandLine (detects obfuscation)
    8. event_frequency_1h         — rolling EventID count per host per hour
    9. is_known_attack_eventid    — binary flag for threat-relevant EventIDs
    10. process_name_entropy      — Shannon entropy of process executable name
"""

import logging
import math
import os
from typing import List

import pandas as pd

logger = logging.getLogger(__name__)

# Known threat-relevant Windows Event IDs (ground-truth security signals)
ATTACK_EVENT_IDS: frozenset = frozenset(
    {
        4625,  # Failed logon
        4688,  # Process creation
        4720,  # User account created
        4732,  # Member added to security-enabled local group
        4672,  # Special privileges assigned to new logon
        7045,  # New service installed
        4624,  # Successful logon
        4698,  # Scheduled task created
        4702,  # Scheduled task updated
        4740,  # Account locked out
    }
)


def calculate_entropy(text: str) -> float:
    """Compute Shannon entropy of a string.

    Used to detect obfuscated command lines and randomly-named executables.
    High entropy (>4.5) indicates potential base64/encoded payloads.
    Low entropy (<2.0) indicates predictable, human-readable strings.

    Args:
        text: Input string to compute entropy for.

    Returns:
        Shannon entropy value in bits. Returns 0.0 for empty or single-char strings.
    """
    if not text or len(text) < 2:
        return 0.0
    prob = [text.count(c) / len(text) for c in set(text)]
    return round(-sum(p * math.log2(p) for p in prob if p > 0), 4)


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute all 10 domain-informed security features on parsed log events.

    This function must be called ONCE on the merged unified DataFrame (Atomic +
    Windows-APT combined), NOT separately per dataset. Calling it on separate
    DataFrames before merging causes `unusual_process_parent_ratio` values to
    be dataset-size-dependent, which leaks dataset identity into the feature.

    All temporal features (session_duration, time_delta_prev_event,
    event_frequency_1h) require valid TimeCreated timestamps. If timestamps
    are missing or unparseable, these features default to 0.0 gracefully.

    Args:
        df: Input DataFrame containing parsed log fields. Must have at minimum
            an EventID column. All other columns have safe defaults.

    Returns:
        DataFrame enriched with 10 numerical security features and a 'label'
        column. Original columns are preserved. Temporary computation columns
        (is_failed_login, parent_child, prev_time) are dropped before return.

    Raises:
        ValueError: If the input DataFrame is None (not for empty DataFrames,
            which return immediately).
    """
    if df is None:
        raise ValueError("engineer_features received None DataFrame.")
    if df.empty:
        logger.warning("engineer_features called on empty DataFrame — returning as-is.")
        return df

    out = df.copy()

    # ── Ensure required columns exist with safe defaults ─────────────────────
    _COLUMN_DEFAULTS = [
        ("EventID", 0),
        ("CommandLine", ""),
        ("ProcessName", ""),
        ("ParentProcessName", ""),
        ("Computer", "CORP-HOST-01"),
        ("TargetUserName", "administrator"),
    ]
    for col, default_val in _COLUMN_DEFAULTS:
        if col not in out.columns:
            out[col] = default_val

    # ── Parse and sort by TimeCreated ────────────────────────────────────────
    timestamps_valid = False
    if "TimeCreated" in out.columns and not out["TimeCreated"].isnull().all():
        out["TimeCreated"] = pd.to_datetime(out["TimeCreated"], errors="coerce")
        if out["TimeCreated"].isnull().any():
            out["TimeCreated"] = out["TimeCreated"].ffill().bfill().fillna(pd.Timestamp("2024-01-01T00:00:00Z"))
        out = out.sort_values("TimeCreated").reset_index(drop=True)
        timestamps_valid = True
    else:
        out["TimeCreated"] = pd.Timestamp("2024-01-01T00:00:00Z")

    # ── Feature 1: failed_login_count_5m ─────────────────────────────────────
    out["is_failed_login"] = (out["EventID"] == 4625).astype(int)
    if timestamps_valid:
        try:
            out_temp = out.set_index("TimeCreated")
            out["failed_login_count_5m"] = out_temp["is_failed_login"].rolling("5min", closed="left").sum().values
        except Exception as exc:
            logger.warning("failed_login_count_5m rolling failed: %s — defaulting to 0.", exc)
            out["failed_login_count_5m"] = 0.0
    else:
        out["failed_login_count_5m"] = 0.0

    # ── Feature 2: time_delta_prev_event ─────────────────────────────────────
    # Sort by TimeCreated before groupby-shift to ensure monotonic ordering per host.
    if timestamps_valid:
        out["prev_time"] = out.sort_values("TimeCreated").groupby("Computer")["TimeCreated"].shift(1)
        out["time_delta_prev_event"] = (
            (out["TimeCreated"] - out["prev_time"]).dt.total_seconds().fillna(0.0).clip(lower=0.0)
        )
        out.drop(columns=["prev_time"], inplace=True, errors="ignore")
    else:
        out["time_delta_prev_event"] = 0.0

    # ── Feature 3: is_powershell_executed ────────────────────────────────────
    cmd_str: pd.Series = out["CommandLine"].fillna("").astype(str).str.lower()
    proc_str: pd.Series = out["ProcessName"].fillna("").astype(str).str.lower()

    _PS_PROC_TERMS: List[str] = ["powershell", "pwsh", "powershell_ise"]
    _PS_CMD_TERMS: List[str] = [
        "powershell",
        "pwsh",
        "-encodedcommand",
        "-enc ",
        "-e ",
        "downloadstring",
        "iex",
        "bypass",
        "-w hidden",
        "-nop",
        "sqb",
        "awv4",
        "cabo",
    ]
    has_ps_proc = proc_str.apply(lambda p: any(t in p for t in _PS_PROC_TERMS))
    has_ps_cmd = cmd_str.apply(lambda c: any(t in c for t in _PS_CMD_TERMS))
    out["is_powershell_executed"] = (has_ps_proc | has_ps_cmd).astype(int)

    # ── Feature 4: privilege_escalation_flag ─────────────────────────────────
    out["privilege_escalation_flag"] = out["EventID"].isin([4672, 4720, 4732]).astype(int)

    # ── Feature 5: unusual_process_parent_ratio ───────────────────────────────
    # CRITICAL FIX: Normalize by max_count (most frequent pair), NOT total rows.
    # Using total rows made the ratio DataFrame-size-dependent, which caused the
    # feature value to change depending on which dataset subset was passed in.
    # With max_count normalization: most common pair = 0.0, unique pairs ≈ 1.0.
    # This is now consistent regardless of DataFrame size.
    out["parent_child"] = out["ParentProcessName"].fillna("unknown") + "->" + out["ProcessName"].fillna("unknown")
    pair_counts: pd.Series = out["parent_child"].value_counts()
    max_count: int = max(int(pair_counts.max()), 1)
    out["unusual_process_parent_ratio"] = out["parent_child"].map(lambda x: 1.0 - (pair_counts.get(x, 1) / max_count))

    # ── Feature 6: session_duration ──────────────────────────────────────────
    # CRITICAL FIX: Group by [Computer, TargetUserName] instead of just TargetUserName.
    # The old groupby("TargetUserName") mixed events from different hosts under
    # the same username, collapsing multi-host sessions into one.
    if timestamps_valid:
        group_keys: List[str] = [k for k in ["Computer", "TargetUserName"] if k in out.columns]
        if group_keys:
            user_start: pd.Series = out.groupby(group_keys)["TimeCreated"].transform("min")
            out["session_duration"] = (out["TimeCreated"] - user_start).dt.total_seconds().fillna(0.0).clip(lower=0.0)
        else:
            out["session_duration"] = 0.0
    else:
        out["session_duration"] = 0.0

    # ── Feature 7: commandline_entropy ───────────────────────────────────────
    # High entropy → obfuscated/base64-encoded payload (malicious signal)
    # Low entropy → human-readable benign command
    out["commandline_entropy"] = out["CommandLine"].fillna("").astype(str).apply(calculate_entropy)

    # ── Feature 8: event_frequency_1h ────────────────────────────────────────
    # Rolling count of same EventID per host per 1-hour window.
    # Brute-force attacks (4625 bursts) and lateral movement (4688 spikes) show
    # elevated frequency. Benign baseline is steady-state.
    if timestamps_valid:
        try:
            out_indexed = out.set_index("TimeCreated")
            freq_series = (
                out_indexed.groupby(["Computer", "EventID"])["EventID"]
                .rolling("1h", min_periods=1)
                .count()
                .reset_index(level=[0, 1], drop=True)
            )
            out["event_frequency_1h"] = freq_series.values.astype(float)
        except Exception as exc:
            logger.warning("event_frequency_1h rolling failed: %s — defaulting to 1.0.", exc)
            out["event_frequency_1h"] = 1.0
    else:
        out["event_frequency_1h"] = 1.0

    # ── Feature 9: is_known_attack_eventid ───────────────────────────────────
    # Binary flag: 1 if EventID is a known threat-relevant Windows event.
    # Ground truth security signals (not heuristic).
    out["is_known_attack_eventid"] = out["EventID"].isin(ATTACK_EVENT_IDS).astype(int)

    # ── Feature 10: process_name_entropy ─────────────────────────────────────
    # Shannon entropy of the executable basename.
    # Legitimate: low entropy (svchost.exe, explorer.exe, cmd.exe)
    # Malware: high entropy (randomly named executables, packed binaries)
    out["process_name_entropy"] = (
        out["ProcessName"].fillna("").astype(str).apply(lambda x: calculate_entropy(os.path.basename(x)))
    )

    # ── Label generation fallback ────────────────────────────────────────────
    # Per rules.md §2.7: Labels must be generated ONCE during preprocessing.
    # If caller has already set 'label', this block is skipped.
    if "label" not in out.columns:
        out["label"] = (
            (out["is_powershell_executed"] == 1)
            | (out["privilege_escalation_flag"] == 1)
            | (out["failed_login_count_5m"] >= 3)
        ).astype(int)

    # ── Clean up temporary computation columns ───────────────────────────────
    out.drop(columns=["is_failed_login", "parent_child"], inplace=True, errors="ignore")

    return out
