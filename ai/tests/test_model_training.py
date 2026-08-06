"""Unit Tests for Phase 5 Model Training and Evaluation."""

import pytest
import pandas as pd
import numpy as np
from pathlib import Path
from ai.models.trainer import train_candidate_models, prepare_feature_matrix
from ai.models.evaluator import evaluate_model_performance
from sklearn.ensemble import RandomForestClassifier


def test_prepare_feature_matrix():
    """Test feature matrix extraction and scaling."""
    df = pd.DataFrame([
        {
            "failed_login_count_5m": 0,
            "is_powershell_executed": 0,
            "privilege_escalation_flag": 0,
            "unusual_process_parent_ratio": 0.1,
            "session_duration": 10,
        },
        {
            "failed_login_count_5m": 5,
            "is_powershell_executed": 1,
            "privilege_escalation_flag": 1,
            "unusual_process_parent_ratio": 0.9,
            "session_duration": 300,
        },
    ])
    X, y, scaler = prepare_feature_matrix(df)
    assert not X.empty
    assert len(y) == 2
    assert y.iloc[1] == 1


def test_train_candidate_models(tmp_path):
    """Test full training pipeline execution and artifact saving."""
    train_data = []
    for i in range(20):
        train_data.append({
            "failed_login_count_5m": i,
            "is_powershell_executed": i % 2,
            "privilege_escalation_flag": i % 2,
            "unusual_process_parent_ratio": 0.1 * i,
            "session_duration": 10 * i,
            "scenario_id": f"s_{i}",
        })
    train_df = pd.DataFrame(train_data)

    val_data = []
    for i in range(10):
        val_data.append({
            "failed_login_count_5m": i,
            "is_powershell_executed": i % 2,
            "privilege_escalation_flag": i % 2,
            "unusual_process_parent_ratio": 0.1 * i,
            "session_duration": 10 * i,
            "scenario_id": f"v_{i}",
        })
    val_df = pd.DataFrame(val_data)

    metadata = train_candidate_models(train_df, val_df, artifacts_dir=tmp_path)

    assert "model_name" in metadata
    assert (tmp_path / "best_model.pkl").exists()
    assert (tmp_path / "preprocessor.pkl").exists()
    assert (tmp_path / "feature_names.json").exists()
    assert (tmp_path / "metadata.json").exists()
    assert (tmp_path / "VERSION.md").exists()
