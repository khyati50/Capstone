"""Domain-Informed Security Feature Engineering Pipeline.

Calculates behavioral threat detection features:
- failed_login_count_5m: Cumulative failed logins (Event ID 4625) within 5-min window
- time_delta_prev_event: Elapsed seconds since previous event on same host/user
- is_powershell_executed: Advanced indicator for PowerShell/pwsh & encoded payload launch
- privilege_escalation_flag: Boolean indicator for Event 4672 / Sysmon Event 1
- unusual_process_parent_ratio: Frequency ratio for parent-child process relationship
- session_duration: Total duration of active user session
- label: Prepared ground-truth binary threat label generated once during preprocessing
"""

import pandas as pd
import math


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of command-line string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return round(-sum(p * math.log2(p) for p in prob), 4)


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Calculate domain-informed security features and prepared label on parsed logs.

    Args:
        df: Input DataFrame containing parsed log fields.

    Returns:
        DataFrame enriched with numerical security features and prepared 'label' column.
    """
    if df.empty:
        return df

    out = df.copy()

    # Ensure sorting & datetime parsing on TimeCreated
    if "TimeCreated" in out.columns and not out["TimeCreated"].isnull().all():
        out["TimeCreated"] = pd.to_datetime(out["TimeCreated"], errors="coerce")
        out = out.sort_values("TimeCreated").reset_index(drop=True)
    else:
        out["TimeCreated"] = pd.Timestamp.now()

    # Ensure default columns exist to prevent KeyErrors on sparse DataFrames
    for col, default_val in [
        ("EventID", 0),
        ("CommandLine", ""),
        ("ProcessName", ""),
        ("ParentProcessName", ""),
        ("Computer", "CORP-HOST-01"),
        ("TargetUserName", "administrator"),
    ]:
        if col not in out.columns:
            out[col] = default_val

    # 1. failed_login_count_5m (EventID 4625 rolling count)
    out["is_failed_login"] = (out["EventID"] == 4625).astype(int)
    try:
        out_temp = out.set_index("TimeCreated")
        out["failed_login_count_5m"] = out_temp["is_failed_login"].rolling("5min", closed="left").sum().values
    except Exception:
        out["failed_login_count_5m"] = 0

    # 2. time_delta_prev_event
    if "TimeCreated" in out.columns:
        out["prev_time"] = out.groupby("Computer")["TimeCreated"].shift(1)
        out["time_delta_prev_event"] = (out["TimeCreated"] - out["prev_time"]).dt.total_seconds().fillna(0)
        out.drop(columns=["prev_time"], inplace=True, errors="ignore")
    else:
        out["time_delta_prev_event"] = 0.0

    # 3. Expanded is_powershell_executed (pwsh.exe, encoded command, base64 indicators, IEX)
    cmd_str = out["CommandLine"].fillna("").astype(str).str.lower()
    proc_str = out["ProcessName"].fillna("").astype(str).str.lower()

    ps_proc_terms = ["powershell", "pwsh", "powershell_ise"]
    ps_cmd_terms = [
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

    has_ps_proc = proc_str.apply(lambda p: any(t in p for t in ps_proc_terms))
    has_ps_cmd = cmd_str.apply(lambda c: any(t in c for t in ps_cmd_terms))
    out["is_powershell_executed"] = (has_ps_proc | has_ps_cmd).astype(int)

    # 4. privilege_escalation_flag (EventID 4672 / Admin creation 4720 / Group escalation 4732)
    out["privilege_escalation_flag"] = (out["EventID"].isin([4672, 4720, 4732])).astype(int)

    # 5. unusual_process_parent_ratio
    out["parent_child"] = out["ParentProcessName"].fillna("unknown") + "->" + out["ProcessName"].fillna("unknown")
    pair_counts = out["parent_child"].value_counts()
    total_count = len(out)
    out["unusual_process_parent_ratio"] = out["parent_child"].map(lambda x: 1.0 - (pair_counts.get(x, 1) / total_count))

    # 6. session_duration
    if "TimeCreated" in out.columns:
        user_start = out.groupby("TargetUserName")["TimeCreated"].transform("min")
        out["session_duration"] = (out["TimeCreated"] - user_start).dt.total_seconds().fillna(0)
    else:
        out["session_duration"] = 0.0

    # 7. Item 2: Explicit Label Generation during Preprocessing (stored in 'label' column)
    if "label" not in out.columns:
        out["label"] = (
            (out["is_powershell_executed"] == 1)
            | (out["privilege_escalation_flag"] == 1)
            | (out["failed_login_count_5m"] >= 3)
        ).astype(int)

    # Clean up temporary columns
    out.drop(columns=["is_failed_login", "parent_child"], inplace=True, errors="ignore")

    return out
