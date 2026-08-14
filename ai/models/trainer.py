"""Multi-Model Training & Production Artifact Generation Protocol.

Trains candidate models:
1. Random Forest (Tree Ensemble)
2. XGBoost (Gradient Boosted Trees)
3. Decision Tree (Baseline)
4. Isolation Forest (Unsupervised Anomaly Detection Baseline)

Evaluates on validation split, selects best model, and saves production artifacts to
ai/models/artifacts/ (best_model.pkl, feature_names.json, preprocessor.pkl, metadata.json, VERSION.md).
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

from ai.config import ARTIFACTS_DIR, NUMERICAL_FEATURES, RANDOM_STATE
from ai.models.evaluator import evaluate_model_performance


def prepare_feature_matrix(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, StandardScaler]:
    """Extract and scale numerical features for model training using prepared labels.

    Args:
        df: Input DataFrame containing engineered features and prepared 'label' column.

    Returns:
        Tuple of (X_matrix, y_series, scaler).
    """
    if df.empty:
        return pd.DataFrame(), pd.Series(dtype=int), StandardScaler()

    feature_cols = [c for c in NUMERICAL_FEATURES if c in df.columns]
    X = df[feature_cols].fillna(0.0).copy()

    # Ground truth label: consume prepared 'label' column generated during preprocessing
    if "label" in df.columns:
        y = df["label"].astype(int)
    else:
        # Preprocessing fallback to ensure y is always present
        y = (
            (df.get("is_powershell_executed", 0) == 1)
            | (df.get("privilege_escalation_flag", 0) == 1)
            | (df.get("failed_login_count_5m", 0) >= 3)
        ).astype(int)

    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)

    return X_scaled, y, scaler


def train_candidate_models(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    artifacts_dir: Path = ARTIFACTS_DIR,
) -> Dict[str, Any]:
    """Train all candidate models, evaluate on validation set, and save best model.

    Args:
        train_df: Training split DataFrame.
        val_df: Validation split DataFrame.
        artifacts_dir: Target folder to store production model artifacts.

    Returns:
        Comparison summary dictionary.
    """
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    X_train, y_train, scaler = prepare_feature_matrix(train_df)
    X_val, y_val, _ = prepare_feature_matrix(val_df)

    if X_train.empty or X_val.empty:
        return {"error": "Empty training or validation dataset"}

    # Define candidate models with strict anti-overfitting regularization
    candidates = {
        "RandomForest": RandomForestClassifier(
            n_estimators=50,
            max_depth=5,
            min_samples_split=10,
            min_samples_leaf=4,
            max_features="sqrt",
            random_state=RANDOM_STATE,
        ),
        "XGBoost": XGBClassifier(
            n_estimators=50,
            max_depth=4,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_alpha=1.0,
            reg_lambda=2.0,
            random_state=RANDOM_STATE,
            eval_metric="logloss",
        ),
        "DecisionTree": DecisionTreeClassifier(
            max_depth=4,
            min_samples_split=10,
            min_samples_leaf=5,
            random_state=RANDOM_STATE,
        ),
    }

    results = {}
    best_f1 = -1.0
    best_model_name = ""
    best_model_obj = None

    for name, model in candidates.items():
        print(f"Training candidate model: {name}...")
        model.fit(X_train, y_train)
        metrics = evaluate_model_performance(model, X_val, y_val, model_name=name)
        results[name] = metrics

        if metrics["f1_score"] > best_f1:
            best_f1 = metrics["f1_score"]
            best_model_name = name
            best_model_obj = model

    # Train Isolation Forest baseline
    iso = IsolationForest(contamination=0.1, random_state=RANDOM_STATE)
    iso.fit(X_train)
    iso_preds = np.where(iso.predict(X_val) == -1, 1, 0)
    iso_metrics = {
        "model_name": "IsolationForest",
        "accuracy": round(float((iso_preds == y_val).mean()), 4),
        "f1_score": round(float((iso_preds & y_val).sum() / max(1, (iso_preds | y_val).sum())), 4),
    }
    results["IsolationForest"] = iso_metrics

    # Fallback to RandomForest if no model beat baseline
    if best_model_obj is None:
        best_model_name = "RandomForest"
        best_model_obj = candidates["RandomForest"]

    print(f"\nBest Production Model Selected: {best_model_name} (Val F1: {best_f1:.4f})")

    # Save artifacts
    joblib.dump(best_model_obj, artifacts_dir / "best_model.pkl")
    joblib.dump(scaler, artifacts_dir / "preprocessor.pkl")

    feature_names = list(X_train.columns)
    with open(artifacts_dir / "feature_names.json", "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2)

    metadata = {
        "model_name": best_model_name,
        "selected_f1_score": best_f1,
        "trained_at": datetime.now().isoformat(),
        "feature_count": len(feature_names),
        "evaluation_summary": results,
    }
    with open(artifacts_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    version_md = f"""# Model Version Log

## Version: v1.0.0
- **Selected Model:** {best_model_name}
- **Validation F1-Score:** {best_f1:.4f}
- **Training Timestamp:** {metadata['trained_at']}
- **Input Features ({len(feature_names)}):** {', '.join(feature_names)}
- **Candidate Models Evaluated:** RandomForest, XGBoost, DecisionTree, IsolationForest
"""
    with open(artifacts_dir / "VERSION.md", "w", encoding="utf-8") as f:
        f.write(version_md)

    print(f"Production artifacts saved to {artifacts_dir}")
    return metadata
