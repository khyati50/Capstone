"""Model Performance Evaluation Module.

Evaluates candidate models across metrics:
- Accuracy, Precision, Recall, F1-Score, ROC-AUC
- Confusion Matrix
- Inference Latency (ms per prediction)
"""

import time
from typing import Any, Dict
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)


def evaluate_model_performance(
    model: Any,
    X_eval: pd.DataFrame,
    y_eval: pd.Series,
    model_name: str = "CandidateModel",
) -> Dict[str, Any]:
    """Calculate comprehensive classification metrics and inference speed.

    Args:
        model: Trained model object with predict and predict_proba.
        X_eval: Feature matrix for evaluation.
        y_eval: Ground truth binary labels.
        model_name: Descriptive name of the model.

    Returns:
        Dictionary of evaluation metrics.
    """
    if X_eval.empty or y_eval.empty:
        return {"model_name": model_name, "error": "Empty evaluation dataset"}

    start_time = time.time()
    preds = model.predict(X_eval)
    latency_ms = ((time.time() - start_time) / len(X_eval)) * 1000.0

    probs = None
    if hasattr(model, "predict_proba"):
        try:
            probs = model.predict_proba(X_eval)[:, 1]
        except Exception:
            pass

    acc = float(accuracy_score(y_eval, preds))
    prec = float(precision_score(y_eval, preds, zero_division=0))
    rec = float(recall_score(y_eval, preds, zero_division=0))
    f1 = float(f1_score(y_eval, preds, zero_division=0))

    roc_auc = 0.5
    if probs is not None and len(np.unique(y_eval)) > 1:
        try:
            roc_auc = float(roc_auc_score(y_eval, probs))
        except Exception:
            pass

    cm = confusion_matrix(y_eval, preds).tolist()

    return {
        "model_name": model_name,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": cm,
        "inference_latency_ms": round(latency_ms, 4),
        "eval_sample_count": len(X_eval),
    }
