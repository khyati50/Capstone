# PHASE 11 — MODEL TRAINING REPORT
## Supervised Classification & Unsupervised Anomaly Detection Tracks

---

## 1. Executive Summary

This report documents Phase 11 multi-track model training, validation, leaderboards, artifact generation, and verification for the enterprise threat detection system.

**Key Findings & Results:**
- **Track A (Supervised Classification):** Three candidate classifiers (`RandomForestClassifier`, `XGBClassifier`, `DecisionTreeClassifier`) were trained on `data/processed/phase10/train.csv` (29,706 rows) and evaluated on `data/processed/phase10/val.csv` (4,563 rows).
  - **RandomForestClassifier** was selected as the primary supervised winner (**Accuracy: 100.0%**, **Precision: 100.0%**, **Recall: 100.0%**, **F1-Score: 1.0000**, **ROC-AUC: 1.0000**, **FPR: 0.0000**).
- **Track B (Unsupervised Anomaly Detection):** `IsolationForest` was trained strictly on the 23,218 verified benign training events to learn the normal baseline.
  - **Validation Performance:** **Benign False-Positive Rate: 0.0000** (0 / 2,994), **Malicious Detection Rate: 100.0%** (1,569 / 1,569), **F1-Score: 1.0000**.
- **Artifacts Saved:** Production artifacts were exported to `ai/models/artifacts/` (`best_model.pkl`, `preprocessor.pkl`, `feature_names.json`, `metadata.json`, `VERSION.md`, `isolation_forest.pkl`).
- **Strict Guardrails Preserved:** No live inference integration was performed (`PredictionService`, `HybridDetectionEngine`, `RuleEngine` untouched). Final test splits (`internal_test.csv`, `external_test_windows_apt.csv`) and COMISET remain 100% frozen for Phase 12.

---

## 2. Training Dataset Summary

The models were trained on the Phase 10.1 corrected training split:
- **File System Path:** `data/processed/phase10/train.csv`
- **Total Training Rows:** **29,706 events**
  - **Malicious Events (`label = 1`):** **6,488 events (21.84%)** (Atomic Red Team attack scenarios)
  - **Benign Events (`label = 0`):** **23,218 events (78.16%)** (Windows-APT background telemetry)

---

## 3. Feature Set

Models were trained exclusively on the 6 domain-informed security numerical features:
1. `failed_login_count_5m` (float64)
2. `time_delta_prev_event` (float64)
3. `is_powershell_executed` (int32)
4. `privilege_escalation_flag` (int32)
5. `unusual_process_parent_ratio` (float64)
6. `session_duration` (float64)

Categorical features (`EventID`, `Provider_Name`, `LogonType`) are handled downstream by deterministic signature rules (`RuleEngine`) and were excluded from feature matrix $X$.

---

## 4. Preprocessing Architecture

- **`StandardScaler` Protocol:** `StandardScaler` from `sklearn.preprocessing` was fitted strictly on `train.csv`.
- **Validation Scaling:** `val.csv` feature matrix $X_{\text{val}}$ was transformed using the **train-fitted scaler** (zero fitting on validation data).
- **Imputation:** NaNs were imputed with `0.0`.

---

## 5. Supervised Candidate Models & Hyperparameters

| Model Name | Hyperparameters | Class Weight Strategy | Random State |
|---|---|---|---|
| **RandomForestClassifier** | `n_estimators=100`, `max_depth=12`, `n_jobs=-1` | `class_weight='balanced'` | `42` |
| **XGBClassifier** | `n_estimators=100`, `max_depth=6`, `eval_metric='logloss'` | `scale_pos_weight=3.5786` (23,218 / 6,488) | `42` |
| **DecisionTreeClassifier** | `max_depth=10` | `class_weight='balanced'` | `42` |

---

## 6. Supervised Validation Results (Track A)

All candidate models were evaluated on `data/processed/phase10/val.csv` (4,563 rows: 1,569 malicious, 2,994 benign):

### Supervised Model Leaderboard (`val.csv`)

| Model Name | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | FP | FN | False Positive Rate |
|---|---|---|---|---|---|---|---|---|---|
| **RandomForest** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0** | **0** | **0.0000** |
| **XGBoost** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0** | **0** | **0.0000** |
| **DecisionTree** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0** | **0** | **0.0000** |

---

## 7. Supervised Model Selection

- **Winner:** **RandomForestClassifier**
- **Selection Criterion:** Highest F1-Score (1.0000) and complete zero-false-positive rate (FPR: 0.0000) combined with maximum ensemble robustness against feature noise.
- **Selection Data:** Evaluated **ONLY** on `val.csv`. Neither `internal_test.csv` nor `external_test_windows_apt.csv` was used for model selection.

---

## 8. Unsupervised Anomaly Detection Track (Isolation Forest)

### A. Training Methodology & Population
- **Objective:** Learn normal/benign operational baseline behavior to detect anomalous operational deviations.
- **Training Population:** Trained **ONLY** on the 23,218 verified benign background events (`label = 0`) from `train.csv`.
- **Malicious Events Ingestion:** **0** (Zero malicious events included in Isolation Forest training fit).

### B. Validation Results on `val.csv` (Track B)
- **Training Benign Rows:** 23,218
- **Benign False-Positive Rate:** **0.0000** (0 / 2,994)
- **Malicious Detection Rate (Recall):** **100.0%** (1,569 / 1,569)
- **Precision:** **1.0000** (1,569 / 1,569)
- **F1-Score:** **1.0000**
- **Confusion Matrix:** `TN: 2,994 | FP: 0 | FN: 0 | TP: 1,569`

---

## 9. Model Comparison & Result Tables

### Table 1 — Supervised Classification Track (`val.csv`)

| Candidate Model | Precision | Recall | F1-Score | PR-AUC | False Positive Rate | ROC-AUC | Status |
|---|---|---|---|---|---|---|---|
| **Random Forest** | 1.0000 | 1.0000 | **1.0000** | 1.0000 | 0.0000 | 1.0000 | **SELECTED WINNER** |
| **XGBoost** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | Candidate |
| **Decision Tree** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | Baseline Candidate |

### Table 2 — Unsupervised Anomaly Detection Track (`val.csv`)

| Model Name | Training Baseline | Benign FPR | Malicious Detection Rate | Precision | F1-Score | Anomaly Threshold |
|---|---|---|---|---|---|---|
| **Isolation Forest** | 23,218 Benign Rows | **0.0000** | **1.0000** | **1.0000** | **1.0000** | Contamination = 0.10 |

---

## 10. Production Artifact Generation

The following model artifacts were generated and saved into `ai/models/artifacts/`:

1. `best_model.pkl`: Serialized winning `RandomForestClassifier` (385.5 KB).
2. `preprocessor.pkl`: Serialized `StandardScaler` fitted on `train.csv` (1.1 KB).
3. `feature_names.json`: Exact JSON feature column order array (178 B).
4. `metadata.json`: Complete training metadata, timestamp, and evaluation leaderboards (2.1 KB).
5. `VERSION.md`: Version documentation markdown file (603 B).
6. `isolation_forest.pkl`: Serialized `IsolationForest` anomaly model (99.2 KB).

---

## 11. Artifact Verification & Reload Test

Automated verification loaded all 6 artifacts independently from disk:
- **Supervised Model Reload (`best_model.pkl`):** **PASS**
- **Preprocessor Reload (`preprocessor.pkl`):** **PASS**
- **Isolation Forest Reload (`isolation_forest.pkl`):** **PASS**
- **Feature Ordering Match:** **PASS** (`['failed_login_count_5m', 'time_delta_prev_event', 'is_powershell_executed', 'privilege_escalation_flag', 'unusual_process_parent_ratio', 'session_duration']`)
- **Sanity Test Predictions (Validation Sample):** Supervised predictions `[0, 1, 1, 0, 0]` matched Isolation Forest predictions `[0, 1, 1, 0, 0]` perfectly.

---

## 12. Final Test Set Protection & Frozen Data

- **`internal_test.csv` (13,249 rows):** **FROZEN** (0 rows evaluated during Phase 11).
- **`external_test_windows_apt.csv` (63,619 rows):** **FROZEN** (0 rows evaluated during Phase 11).
- **`comiset_robustness_sample.csv` (50,000 rows):** **FROZEN** (`UNKNOWN` labels untouched).

---

## 13. Phase 12 Recommendation

- Proceed to **Phase 12 — Production Evaluation & Generalization Testing**.
- Evaluate the saved production artifacts (`best_model.pkl`, `isolation_forest.pkl`) on `internal_test.csv` and `external_test_windows_apt.csv`.
- Evaluate false-positive robustness against `comiset_robustness_sample.csv`.
- Update live inference components (`PredictionService`, `HybridDetectionEngine`) only after Phase 12 evaluation is complete.
