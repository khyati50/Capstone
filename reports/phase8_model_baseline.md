# PHASE 8 — CURRENT MODEL BASELINE REPORT

```text
CURRENT BASELINE

Model: Built-in Rule-Assisted Heuristic Decision Engine (v1.0.0-heuristic-fallback) / Hybrid ML Pipeline
Model file: Not available in repository — no pre-trained .pkl file present in ai/models/artifacts/
Model version: v1.0.0-heuristic-fallback
Feature count: 6 Numerical + 3 Categorical (9 Total Features)
Evaluation samples: Not available — no appropriate labeled evaluation set exists.
Accuracy: Not available — no appropriate labeled evaluation set exists.
Precision: Not available — no appropriate labeled evaluation set exists.
Recall: Not available — no appropriate labeled evaluation set exists.
F1: Not available — no appropriate labeled evaluation set exists.
ROC-AUC: Not available — no appropriate labeled evaluation set exists.
PR-AUC: Not available — no appropriate labeled evaluation set exists.
False positives: Not available — no appropriate labeled evaluation set exists.
False negatives: Not available — no appropriate labeled evaluation set exists.
```

---

## 1. Executive Summary

This report establishes a reproducible baseline for the **CURRENT** threat detection machine learning and inference pipeline in the capstone repository prior to any dataset integration or model retraining in Phase 9.

**Key Findings:**
- **No model changes, retraining, or pipeline modifications were made** during this phase.
- Code path inspection confirms that live inference is served by `PredictionService` (`ai/prediction/service.py`) interlocked with `HybridDetectionEngine` (`ai/detection/hybrid_engine.py`).
- Because `ai/models/artifacts/best_model.pkl` is not currently pre-saved on disk, the inference engine operates using its built-in rule-assisted decision fallback (`v1.0.0-heuristic-fallback`).
- No formal labeled evaluation dataset exists in `ai/models/artifacts/` for baseline metric scoring; metrics are accurately reported as unavailable rather than fabricated.
- Baseline inference sanity tests and reproducibility checks confirm **100% deterministic operation**.

---

## 2. Current Model Identification

- **Algorithm / Type:** Built-in Rule-Assisted Heuristic Decision Engine (`PredictionService`) / Candidate architecture prepared for `RandomForestClassifier` (`ai/models/trainer.py`).
- **Training Library:** `scikit-learn` (`sklearn.ensemble.RandomForestClassifier`, `sklearn.preprocessing.StandardScaler`), `xgboost` (`XGBClassifier`), `joblib`.
- **Loading Site:** `PredictionService.load_artifacts()` in `ai/prediction/service.py` (instantiated at FastAPI microservice startup in `ai/server.py`).
- **Prediction Site:** `PredictionService.predict_single()` in `ai/prediction/service.py` called by `HybridDetectionEngine.process_event()` in `ai/detection/hybrid_engine.py`.

---

## 3. Model File and Version

- **Model File Path:** `ai/models/artifacts/best_model.pkl` (Target path defined in `ai/config.py`).
- **Disk Existence:** **Not available in repository** — `ai/models/artifacts/` directory is not currently present on disk.
- **Active Model Version:** `"v1.0.0-heuristic-fallback"`

---

## 4. Training / Model Metadata Available

- **Training Timestamp:** Not available in repository.
- **Training Dataset Name:** Not available in repository.
- **Hyperparameters:**
  - RandomForest Candidate: `n_estimators=50, max_depth=10, random_state=42`
  - XGBoost Candidate: `n_estimators=50, max_depth=6, random_state=42, eval_metric='logloss'`
  - DecisionTree Candidate: `max_depth=8, random_state=42`
  - IsolationForest Candidate: `contamination=0.1, random_state=42`
- **Random Seed:** `RANDOM_STATE = 42` (`ai/config.py`)

---

## 5. Feature List

The current pipeline inspects 9 features across 2 feature groups:

### Numerical Features (6):
1. `failed_login_count_5m` — Cumulative failed login attempts (EventID 4625) within a 5-minute rolling window.
2. `time_delta_prev_event` — Elapsed time in seconds since the previous event on the same host/user context.
3. `is_powershell_executed` — Binary indicator (1/0) for `powershell.exe` execution or encoded payload launch.
4. `privilege_escalation_flag` — Binary indicator (1/0) for admin privilege assignment (EventID 4672 / 4720).
5. `unusual_process_parent_ratio` — Frequency ratio for rare parent-child process execution relationships.
6. `session_duration` — Total active session duration in seconds.

### Categorical Features (3):
7. `EventID` — Windows Event ID (e.g., 4624, 4625, 4688, 4672, 4720, 7045).
8. `Provider_Name` — Event provider source name (e.g., `Microsoft-Windows-Security-Auditing`).
9. `LogonType` — Windows logon type classification code (e.g., Type 2 Interactive, Type 3 Network, Type 10 RemoteInteractive).

---

## 6. Feature Ordering

The exact feature vector input sequence expected by `PredictionService` and `StandardScaler` is:

```json
[
  "failed_login_count_5m",
  "time_delta_prev_event",
  "is_powershell_executed",
  "privilege_escalation_flag",
  "unusual_process_parent_ratio",
  "session_duration"
]
```

---

## 7. Preprocessing Pipeline

1. **Feature Extraction (`ai/preprocessing/feature_engineering.py`)**: Computes 6 domain security features from raw Windows JSON log entries.
2. **Missing Value Imputation**: Missing or null feature values are imputed with `0.0` default.
3. **Scaling (`StandardScaler`)**: Features are normalized using `sklearn.preprocessing.StandardScaler` (`X_scaled = scaler.transform(X_df)`).
4. **Categorical Handling**: Categorical attributes (`EventID`, `Provider_Name`, `LogonType`) pass directly to signature rules and downstream Security Intelligence synthesis.

---

## 8. Inference Pipeline Code Path

```
Raw Windows Event Log JSON
          │
          ▼
POST /predict  ──►  process_event_full_pipeline()  (ai/server.py)
                          │
                          ▼
               HybridDetectionEngine.process_event()  (ai/detection/hybrid_engine.py)
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
   PredictionService.predict_single()   RuleEngine.evaluate_rules()
   (ai/prediction/service.py)           (ai/detection/rule_engine.py)
             │                         │
             └────────────┬────────────┘
                          ▼
               Fused Alert & Confidence (floored at 0.92)
```

---

## 9. Evaluation Dataset & Class Distribution

- **Official Labeled Test Set:** Not available in repository — no pre-saved labeled test dataset exists in `ai/models/artifacts/`.
- **Evaluation Samples:** Not available — no appropriate labeled evaluation set exists.
- **Class Distribution:** Not available — no appropriate labeled evaluation set exists.

---

## 10. Baseline Metrics

All baseline metrics are accurately documented as unavailable due to the absence of a pre-trained model file and labeled test evaluation set on disk:

- **Accuracy:** Not available — no appropriate labeled evaluation set exists.
- **Precision:** Not available — no appropriate labeled evaluation set exists.
- **Recall:** Not available — no appropriate labeled evaluation set exists.
- **F1-Score:** Not available — no appropriate labeled evaluation set exists.
- **ROC-AUC:** Not available — no appropriate labeled evaluation set exists.
- **PR-AUC:** Not available — no appropriate labeled evaluation set exists.
- **False Positives:** Not available — no appropriate labeled evaluation set exists.
- **False Negatives:** Not available — no appropriate labeled evaluation set exists.

---

## 11. Baseline Inference Sanity Test

A controlled sanity check was executed across the 4 core attack simulation scenarios:

| Scenario | Input Feature Highlights | PredictionService Output | Hybrid Engine Alert | Hybrid Confidence | Alert Source |
|---|---|---|---|---|---|
| **FAILED_LOGIN_BURST** | `failed_login_count_5m=1.0` | `pred=0`, `conf=0.95` | `is_alert=True` | `0.815` | `RULE_SIGNATURE_ONLY` |
| **SUSPICIOUS_POWERSHELL** | `is_powershell_executed=1` | `pred=1`, `conf=0.90` | `is_alert=True` | `0.920` | `AI_AND_RULE_AGREEMENT` |
| **PRIVILEGE_ESCALATION** | `privilege_escalation_flag=1` | `pred=1`, `conf=0.90` | `is_alert=True` | `0.920` | `AI_AND_RULE_AGREEMENT` |
| **NEW_ADMIN_ACCOUNT** | `EventID=4720` | `pred=1`, `conf=0.90` | `is_alert=True` | `0.920` | `AI_AND_RULE_AGREEMENT` |

---

## 12. Reproducibility Results

- **Test Method:** Evaluated `PredictionService` and `HybridDetectionEngine` twice sequentially using identical feature inputs.
- **Result:** **100% Deterministic** (`PredictionService Run 1 vs Run 2: Identical`, `HybridEngine Run 1 vs Run 2: Identical`).
- **Reproducibility Status:** **PASSED**.

---

## 13. Known Limitations

1. **Absence of Pre-trained `.pkl` Artifacts:** The repository does not currently contain a pre-trained `best_model.pkl` file; live inference relies on the heuristic fallback engine.
2. **Lack of Labeled Evaluation Set:** No formal benchmark test set is present in `ai/models/artifacts/`.
3. **Rule-Dominated Initial Confidence:** `HybridDetectionEngine` floors alert confidence at 0.92 for AI+Rule agreement.

---

## 14. Phase 9 Recommendations

Phase 9 should address the following requirements prior to model retraining:

1. **Feature Extraction Pipeline:** Implement automated feature extraction across the three audited datasets (Atomic Red Team, Windows-APT 2025, COMISET) to produce feature matrix $X$ matching the 9 core features in `ai/config.py`.
2. **Label Reconciliation:** Construct a balanced dataset pairing attack telemetry (Atomic Red Team / Windows-APT 2025 S01–S10) with benign operational background traffic (Windows-APT background / COMISET stream).
3. **Model Artifact Generation:** Execute `ai/models/trainer.py` to train, evaluate, and save `best_model.pkl`, `preprocessor.pkl`, `feature_names.json`, `metadata.json`, and `VERSION.md` into `ai/models/artifacts/`.
4. **Reproducible Test Evaluation:** Save a dedicated test split to evaluate formal accuracy, precision, recall, F1, ROC-AUC, and confusion matrix metrics.

---
