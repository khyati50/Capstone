# PHASE 9 — ML TRAINING PIPELINE AUDIT REPORT

```text
PHASE 9 ML TRAINING PIPELINE AUDIT

Training code inspected: YES
Trainer entry point identified: YES
Candidate models identified: YES
Feature pipeline verified: YES
Preprocessing verified: YES
Label requirements verified: YES
Train/validation/test strategy verified: YES
Evaluation methodology verified: YES
Artifact generation verified: YES
Training/inference compatibility checked: YES

Model trained: NO
Model artifact created: NO
Existing model modified: NO
Feature pipeline modified: NO
Dataset modified: NO
Phase 10 executed: NO
```

---

## 1. Executive Summary

This report delivers a comprehensive, strictly read-only audit of the Machine Learning Training Architecture and Model Pipeline across the capstone codebase.

**Key Findings:**
- **No model training, artifact creation, or codebase modification was performed** during this phase.
- **Training Entry Point:** `train_candidate_models(train_df, val_df, artifacts_dir)` in `ai/models/trainer.py`.
- **Candidate Models:** 4 candidate architectures implemented (`RandomForestClassifier`, `XGBClassifier`, `DecisionTreeClassifier`, `IsolationForest`).
- **Feature Pipeline:** Training matrix $X$ uses **6 numerical features** (`NUMERICAL_FEATURES`). Categorical features (`EventID`, `Provider_Name`, `LogonType`) pass directly to signature rules (`RuleEngine`).
- **Preprocessing:** `StandardScaler` normalization fitted during training and exported as `preprocessor.pkl`.
- **Artifact Compatibility:** The 5 artifacts produced by `trainer.py` (`best_model.pkl`, `preprocessor.pkl`, `feature_names.json`, `metadata.json`, `VERSION.md`) **100% match** the loading specifications of `PredictionService` (`ai/prediction/service.py`).
- **Critical Training Gap:** `trainer.py` requires pre-extracted DataFrames with a ground-truth `label` column. Raw datasets audited in Phase 7 must be ingested, feature-extracted, labeled, and split in Phase 10 prior to calling `trainer.py`.

---

## 2. Training Entry Point Analysis

- **Primary Entry Point:** `train_candidate_models(train_df: pd.DataFrame, val_df: pd.DataFrame, artifacts_dir: Path)` in `ai/models/trainer.py`.
- **Feature Matrix Extractor:** `prepare_feature_matrix(df: pd.DataFrame)` in `ai/models/trainer.py`.
- **Input Data Format:** Expects pre-processed pandas DataFrames containing engineered numerical feature columns and a ground-truth `label` column.
- **Target Directory:** `ARTIFACTS_DIR = BASE_DIR / "ai" / "models" / "artifacts"` (defined in `ai/config.py`).
- **Unit Test Reference:** `test_train_candidate_models()` in `ai/tests/test_model_training.py`.

---

## 3. Candidate Models Audit

| Candidate Model | Library / Class | Learning Paradigm | Target Label Format | Key Hyperparameters | Implementation Status | Suitability for Binary Threat Detection |
|---|---|---|---|---|---|---|
| **RandomForest** | `sklearn.ensemble.RandomForestClassifier` | Supervised Ensemble | Binary (0/1) | `n_estimators=50`, `max_depth=10`, `random_state=42` | **IMPLEMENTED** | **HIGH** (Robust against overfitting; default production selection) |
| **XGBoost** | `xgboost.XGBClassifier` | Supervised Gradient Boosting | Binary (0/1) | `n_estimators=50`, `max_depth=6`, `random_state=42`, `eval_metric='logloss'` | **IMPLEMENTED** | **HIGH** (Gradient boosted trees suited for tabular security features) |
| **DecisionTree** | `sklearn.tree.DecisionTreeClassifier` | Supervised Tree | Binary (0/1) | `max_depth=8`, `random_state=42` | **IMPLEMENTED** | **MEDIUM** (Interpretable baseline; evaluated for benchmarking) |
| **IsolationForest** | `sklearn.ensemble.IsolationForest` | Unsupervised Anomaly Detection | None (Unsupervised $X$) | `contamination=0.1`, `random_state=42` | **IMPLEMENTED** | **LOW/BASELINE ONLY** (Trained without labels; anomaly scores inverted $-1 \rightarrow 1$) |

---

## 4. Feature Pipeline Audit

The audit verified feature usage across `ai/config.py`, `ai/preprocessing/feature_engineering.py`, `ai/models/trainer.py`, and `ai/prediction/service.py`:

### A. Numerical Features (Trained in ML Model $X$):
1. `failed_login_count_5m` (EventID 4625 rolling count)
2. `time_delta_prev_event` (Host/user timestamp delta)
3. `is_powershell_executed` (PowerShell & encoded command launch)
4. `privilege_escalation_flag` (EventID 4672 / 4720 / 4732)
5. `unusual_process_parent_ratio` (Parent-child frequency ratio)
6. `session_duration` (Active logon duration)

### B. Categorical Features (Passed to Downstream Signature Rules):
7. `EventID` (Windows Event ID)
8. `Provider_Name` (Event log provider)
9. `LogonType` (Logon type code)

### Critical Findings on Feature Handling:
- `trainer.py` extracts ONLY numerical features via `[c for c in NUMERICAL_FEATURES if c in df.columns]`.
- Categorical features are **NOT one-hot encoded** into the ML matrix $X$.
- This design is **INTENTIONAL and INCOMPATIBILITY-FREE**: The 6 numerical features train the ML model for anomaly/pattern scoring, while categorical features pass directly to deterministic signature rules (`RuleEngine`) and Security Intelligence synthesis (`SecurityIntelligenceLayer`).

---

## 5. Preprocessing Audit

- **Scaling Object:** `sklearn.preprocessing.StandardScaler`
- **Training Preprocessing Sequence (`prepare_feature_matrix`):**
  1. Filter numerical feature columns (`NUMERICAL_FEATURES`).
  2. Impute missing/null values with `0.0` (`fillna(0.0)`).
  3. Extract target label `y = df["label"].astype(int)`.
  4. Fit and transform features: `X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)`.
  5. Save scaler artifact: `joblib.dump(scaler, artifacts_dir / "preprocessor.pkl")`.
- **Inference Preprocessing Sequence (`PredictionService.predict_single`):**
  1. Build row vector matching `feature_names.json`.
  2. Transform row: `X_scaled = self.scaler.transform(X_df)`.
- **Train vs Inference Consistency:** **GUARANTEED IDENTICAL**. Scaling algorithm, column ordering, and imputation defaults match 100%.

---

## 6. Label Requirements Audit

- **Target Label Format:** Binary integer (0 = Benign, 1 = Malicious).
- **Target Column Name:** `df["label"]`.
- **Trainer Fallback Logic:** If `label` column is absent from `df`, `trainer.py` derives a heuristic fallback:
  `y = ((is_powershell_executed == 1) | (privilege_escalation_flag == 1) | (failed_login_count_5m >= 3)).astype(int)`
- **Integration Requirement for Audited Datasets (Phase 7):**
  - **Atomic Red Team:** Contains 100% malicious events. Must be assigned `label = 1` and paired with benign telemetry.
  - **COMISET Lab:** Rule levels (0–15) provide metadata. Must be thresholded or paired to establish ground truth.
  - **Windows-APT 2025:** Background telemetry (`label = 0`) and APT scenarios S01–S10 (`label = 1`) provide natural binary balance.

---

## 7. Train / Validation / Test Strategy Audit

- **Input Expectation:** `train_candidate_models()` expects pre-split `train_df` and `val_df` DataFrames.
- **Configured Ratios:** `TRAIN_RATIO = 0.70`, `VAL_RATIO = 0.15`, `TEST_RATIO = 0.15` (`ai/config.py`).
- **Class Balancing:** Currently **MISSING** in `trainer.py` (no `class_weight='balanced'` or oversampling/undersampling configured).
- **Data Leakage Risk:** **HIGH RISK IF RANDOM ROW-SPLIT IS USED**. Splitting cybersecurity logs purely by random row index will cause events from the same host, user session, or attack scenario to appear in both training and validation splits.
- **Phase 10 Requirement:** Group-based or temporal-based splitting (by `scenario_id` / `Computer` / `session_id`) is mandatory.

---

## 8. Evaluation Methodology Audit

- **Evaluation Module:** `evaluate_model_performance()` in `ai/models/evaluator.py`.
- **Metrics Calculated:** Accuracy, Precision, Recall, F1-Score, ROC-AUC, Confusion Matrix ($TN, FP, FN, TP$), Inference Latency (ms per prediction).
- **Selection Criterion:** Candidate model selection ranks models strictly by **Validation F1-Score** (`best_f1 = metrics["f1_score"]`).
- **Status:** **IMPLEMENTED & VERIFIED**.

---

## 9. Artifact Generation Audit

`train_candidate_models()` generates 5 production artifacts in `ai/models/artifacts/`:

| Artifact File | Saved By (`trainer.py`) | Loaded By (`service.py`) | Format | Purpose / Status |
|---|---|---|---|---|
| `best_model.pkl` | `joblib.dump(best_model_obj)` | `joblib.load(model_path)` | Binary Pickle | Selected production classifier |
| `preprocessor.pkl` | `joblib.dump(scaler)` | `joblib.load(scaler_path)` | Binary Pickle | Fitted `StandardScaler` object |
| `feature_names.json` | `json.dump(feature_names)` | `json.load(names_path)` | JSON Array | Feature column names & ordering |
| `metadata.json` | `json.dump(metadata)` | `json.load(meta_path)` | JSON Object | F1 scores, model name, timestamp |
| `VERSION.md` | `f.write(version_md)` | N/A (Doc Artifact) | Markdown | Model provenance log |

**Artifact Compatibility Status:** **100% MATCHED**.

---

## 10. Training ↔ Inference Compatibility Matrix

| Pipeline Stage | Training Component (`trainer.py`) | Inference Component (`service.py`) | Agreement Status |
|---|---|---|---|
| **Input Features** | 6 Numerical (`NUMERICAL_FEATURES`) | 6 Numerical (`self.feature_names`) | **FULL AGREEMENT** |
| **Feature Ordering** | `NUMERICAL_FEATURES` list | Saved `feature_names.json` order | **FULL AGREEMENT** |
| **Preprocessing** | `StandardScaler.fit_transform()` | `StandardScaler.transform()` | **FULL AGREEMENT** |
| **Missing Values** | `.fillna(0.0)` | `.get(col, 0.0)` | **FULL AGREEMENT** |
| **Model Format** | `joblib` object | `joblib` loaded object | **FULL AGREEMENT** |
| **Artifact Paths** | `ARTIFACTS_DIR` (`ai/config.py`) | `ARTIFACTS_DIR` (`ai/config.py`) | **FULL AGREEMENT** |
| **Output Format** | `predict()` (0/1) & `predict_proba()` | `predict_single()` dict output | **FULL AGREEMENT** |

---

## 11. Identified Problems and Architectural Risks

1. **Missing Production Model Artifacts:** `ai/models/artifacts/best_model.pkl` does not currently exist on disk, causing live inference to run via heuristic fallback.
2. **Synthetic Fallback Label Risk:** If a DataFrame without a `label` column is passed to `trainer.py`, the trainer derives labels using the heuristic rule logic, risking circular self-training.
3. **Unbalanced Class Handling:** Neither `RandomForestClassifier` nor `XGBClassifier` in `trainer.py` currently uses `class_weight='balanced'`, which could hurt recall on imbalanced datasets.
4. **Temporal Data Leakage Risk:** Standard random train/val splitting without grouping by scenario or session will artificially inflate validation metrics.
5. **Data Ingestion Gap:** `trainer.py` expects in-memory DataFrames; it lacks dataset readers for raw EVTX, CSV, and streaming ZIP JSON.

---

## 12. Required Changes for Phase 10

Phase 10 must implement the following pipeline components:

1. **Dataset Loader & Converter:** Build an ingestion module to parse raw EVTX (Atomic), CSV (Windows-APT 2025), and streaming ZIP JSON (COMISET).
2. **Feature Extraction Wrapper:** Pass parsed logs through `engineer_features()` (`ai/preprocessing/feature_engineering.py`) to generate the 6 numerical features.
3. **Ground-Truth Label Assignment:** Assign explicit ground-truth binary labels:
   - Atomic Red Team: `label = 1`
   - Windows-APT 2025 APT Scenarios (S01–S10): `label = 1`
   - Windows-APT Background & COMISET Normal Telemetry: `label = 0`
4. **Group-Based Train / Val / Test Splitter:** Implement scenario-aware or session-aware splitting to prevent temporal data leakage.
5. **Class Weighting:** Enable `class_weight='balanced'` in candidate classifiers.
6. **Execution of `train_candidate_models()`:** Execute training to generate and validate production artifacts in `ai/models/artifacts/`.

---

## 13. Phase 10 Recommendation

- **Proceed to Phase 10 (Feature Extraction & Model Retraining)**.
- Use **Atomic Red Team EVTX** + **Windows-APT 2025 Scenarios (S01–S10)** as the malicious training/validation corpus.
- Use **Windows-APT Background Telemetry** + **COMISET Streamed Telemetry** as the benign training/validation background corpus.
- Hold out **Windows-APT Scenarios S07 (APT41) & S08 (Aquatic Panda)** for external generalization evaluation.
- Train candidate models using `train_candidate_models()` to generate production `best_model.pkl` artifacts.

---
