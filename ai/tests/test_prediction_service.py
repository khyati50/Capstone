"""Unit Tests for Phase 6 Prediction Service & FastAPI Endpoints."""

import pytest
from fastapi.testclient import TestClient
from ai.server import app
from ai.prediction.service import PredictionService

client = TestClient(app)


def test_health_endpoint():
    """Test /health status check."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "service" in data


def test_predict_single_endpoint():
    """Test /predict single inference endpoint."""
    payload = {
        "scenario_id": "test_scen",
        "EventID": 4625,
        "failed_login_count_5m": 5.0,
        "time_delta_prev_event": 1.5,
        "is_powershell_executed": 1,
        "privilege_escalation_flag": 1,
        "unusual_process_parent_ratio": 0.8,
        "session_duration": 120.0,
    }
    response = client.post("/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "prediction" in data
    assert "confidence" in data
    assert "shap_values" in data
    assert data["prediction"] in [0, 1]


def test_predict_batch_endpoint():
    """Test /predict/batch endpoint."""
    payload = [
        {"scenario_id": "s1", "EventID": 4624, "failed_login_count_5m": 0.0},
        {"scenario_id": "s2", "EventID": 4625, "failed_login_count_5m": 6.0, "is_powershell_executed": 1},
    ]
    response = client.post("/predict/batch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 2
    assert len(data["predictions"]) == 2
