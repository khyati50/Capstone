# Model Version Log

## Version: v4.0.0 (MAX Real Dataset)
- **Selected Model:** XGBoost
- **Optimized Validation F1-Score:** 0.9680 (Decision Threshold: 0.2006)
- **Data Source:** data\processed\phase10_2 (Windows-APT 2025 + v4 Scenario Supplement)
- **Features (16):** failed_login_count_5m, time_delta_prev_event, is_powershell_executed, is_cmd_or_tool_executed, privilege_escalation_flag, unusual_process_parent_ratio, session_duration, commandline_entropy, process_name_entropy, event_frequency_1h, is_known_attack_eventid, commandline_length, suspicious_tool_count, path_depth, has_admin_keyword, num_digits_cmdline
- **Train samples:** 21,175 | **Val samples:** 4,537
- **Anti-Overfitting:** Regulated depth, L1/L2 regularization, Optuna PR threshold optimization
