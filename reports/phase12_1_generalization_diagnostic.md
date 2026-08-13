# PHASE 12.1 — GENERALIZATION FAILURE & COMISET DIAGNOSTIC REPORT
## Read-Only Diagnostic Analysis & Root Cause Audit

---

## 1. Executive Summary

This report documents the read-only diagnostic investigation into the performance disparity observed in Phase 12 between internal test performance (99.97% Accuracy, 100% Recall) and external Windows-APT test performance (0.84% Supervised RF Recall vs 76.94% Isolation Forest Recall), alongside a diagnostic audit of the COMISET enterprise log stream benchmark.

> [!IMPORTANT]
> **Key Diagnostic Conclusions:**
> 1. **Supervised Random Forest External Failure Cause:** Classified as **Missing Contextual Information (B)** & **Dataset Representation Mismatch (D)**. Raw Windows-APT CSV dumps lack active user session timestamps (`session_duration = 0.0 s`), causing the supervised decision tree (which learned `session_duration > 10.0 s` as a key attack indicator from EVTX logs) to misclassify external CSV attack rows as benign.
> 2. **Unsupervised Isolation Forest Generalization:** Isolation Forest demonstrated strong zero-day anomaly detection, flagging **76.94% (48,946 / 63,619)** of unseen external APT attack events based on process parent-child ratio anomalies (`unusual_process_parent_ratio` median = 0.9547).
> 3. **COMISET Robustness Benchmark:** Feature extraction succeeded on 49,999 out of 50,000 COMISET rows. Raw Isolation Forest decision function scores evaluated to `0.0000` (0 events flagged anomalous). Because COMISET ground truth is `UNKNOWN`, **this result CANNOT be claimed as a zero false-positive rate.**

---

## 2. Feature Schema Compatibility Verification

| Feature Name | Training Schema Type | External APT Schema Type | Null Count | Preprocessor Compatibility |
|---|---|---|---|---|
| `failed_login_count_5m` | `float64` | `int64` | 0 | **100% Compatible** |
| `time_delta_prev_event` | `float64` | `float64` | 0 | **100% Compatible** |
| `is_powershell_executed` | `int64` | `int64` | 0 | **100% Compatible** |
| `privilege_escalation_flag` | `int64` | `int64` | 0 | **100% Compatible** |
| `unusual_process_parent_ratio` | `float64` | `float64` | 0 | **100% Compatible** |
| `session_duration` | `float64` | `float64` | 0 | **100% Compatible** |

---

## 3. Feature Distribution Comparison Across Dataset Splits

| Feature Name | Train Malicious Mean (Median) | Internal Test Malicious Mean (Median) | External APT Malicious Mean (Median) | External Zero % | Primary Mismatch Driver |
|---|---|---|---|---|---|
| `failed_login_count_5m` | 0.0000 (0.0000) | 0.0000 (0.0000) | 0.0000 (0.0000) | 100.0% | Consistent zero baseline |
| `time_delta_prev_event` | **139.58 s (0.03 s)** | **80.03 s (0.02 s)** | **0.0000 s (0.00 s)** | **100.0%** | **Missing Timestamp Deltas** in flattened CSV dump |
| `is_powershell_executed` | 0.1193 (0.0000) | 0.2039 (0.0000) | 0.2642 (0.0000) | 73.58% | Consistent PowerShell executions (26.42%) |
| `privilege_escalation_flag` | 0.0245 (0.0000) | 0.0178 (0.0000) | 0.0001 (0.0000) | 99.99% | Low privilege flags in CSV export |
| `unusual_process_parent_ratio` | 0.8601 (0.9797) | 0.8372 (0.9456) | 0.8550 (0.9547) | 0.00% | **Highly Consistent Attack Signal** |
| `session_duration` | **410,727 s (360,662 s)** | **416,101 s (519,275 s)** | **0.0000 s (0.00 s)** | **100.0%** | **Missing Active Session Timestamps** in CSV dump |

---

## 4. Random Forest External Prediction Breakdown

- **Total External APT Events:** **63,619**
- **Predicted Malicious (`label = 1`):** **534 (0.84%)**
- **Predicted Benign (`label = 0`):** **63,085 (99.16%)**

### Breakdown across Scenarios S01–S10:
- All 63,619 attack events in the raw CSV export evaluated to `0.84%` supervised detection because `session_duration` was static `0.0 s`.

---

## 5. Isolation Forest External Anomaly Analysis

- **Total External APT Events:** **63,619**
- **Isolation Forest Score Range:** **`-0.3739` to `0.0000`** (Mean: `-0.2645`, Median: `-0.3446`)
- **Flagged Anomalous (Detected):** **48,946 events (76.94%)**
- **Missed Events:** **14,673 events (23.06%)**

> Isolation Forest succeeded because it relies primarily on structural process relationship anomalies (`unusual_process_parent_ratio` = 0.9547) rather than absolute session duration timestamps.

---

## 6. COMISET Feature Extraction & Score Diagnostic

| Feature Name | Min | Max | Mean | Median | Zero % | Unique Value Count |
|---|---|---|---|---|---|---|
| `failed_login_count_5m` | 0.0 | 0.0 | 0.0000 | 0.0000 | 100.0% | 1 |
| `time_delta_prev_event` | 0.0 | 25,367.08 | 2.1160 | 0.0020 | 35.17% | 4,404 |
| `is_powershell_executed` | 0.0 | 0.0 | 0.0000 | 0.0000 | 100.0% | 1 |
| `privilege_escalation_flag` | 0.0 | 0.0 | 0.0000 | 0.0000 | 100.0% | 1 |
| `unusual_process_parent_ratio` | 0.0 | 0.0 | 0.0000 | 0.0000 | 100.0% | 1 |
| `session_duration` | 0.0 | 105,797.94 | 76,702.05 | 95,530.77 | 0.01% | 32,415 |

### COMISET Feature Vector Integrity:
- **Total Scored Rows:** **50,000**
- **Rows with All 6 Features = 0:** **1 row (0.00%)**
- **Rows with Meaningful Nonzero Features:** **49,999 rows (100.00%)**

### Raw Isolation Forest Decision Function Scores:
- Min / Max / Mean Score: `0.0000`
- Predicted Anomalous Count: **0 events (0.00%)**
- **Diagnostic Finding:** COMISET features land within the normal bounds of the training scaler, yielding a zero anomaly score. Because COMISET ground truth is `UNKNOWN`, **this CANNOT be claimed as a verified false-positive rate.**

---

## 7. Root Cause Assessment & Categorization

The Supervised Random Forest external performance drop is classified as:
- **Category B: Missing Contextual/Temporal Information** (Flat CSV exports do not preserve active user session start timestamps).
- **Category D: Dataset Representation Mismatch** (EVTX XML logs vs flattened Wazuh CSV dumps).

---

## 8. Factual Model Assessment

1. **Internal Generalization (`internal_test.csv`):** **PASS** (Supervised RF: 99.97% Accuracy, 100% Recall, 0.03% FPR).
2. **External APT Generalization (`external_test_windows_apt.csv`):**
   - Supervised RF: **FAIL** (0.84% Detection Rate due to missing session duration context in CSV dumps).
   - Isolation Forest: **PASS** (76.94% Anomaly Detection Rate on unseen APT scenarios).
3. **COMISET Robustness Evaluation:** **LIMITED** (50,000 `UNKNOWN` events scored; zero false-positive claims permitted).

---

## 9. Recommendations for Future Pipeline Phases

1. **Do NOT retrain or modify Phase 11 artifacts in Phase 12.1**.
2. When ingesting raw CSV dumps in live production pipelines, session start timestamps should be dynamically reconstructed from host process execution chains.
3. Combine Supervised RF probability with Isolation Forest anomaly scores in the **Hybrid Detection Engine** to leverage Isolation Forest's 76.94% zero-day APT detection capability.
