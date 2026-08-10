"""Comprehensive FastAPI API Endpoint Tests.

Tests all HTTP endpoints for correct status codes, response schemas,
edge cases, error handling, and contract validation.
"""

import pytest
from fastapi.testclient import TestClient
from ai.server import app

client = TestClient(app)


# ──────────────────────────────────────────────
# Root Endpoint Tests
# ──────────────────────────────────────────────


class TestRootEndpoint:
    """Tests for GET / root welcome endpoint."""

    def test_root_returns_200(self):
        """Root endpoint must return HTTP 200."""
        response = client.get("/")
        assert response.status_code == 200

    def test_root_contains_required_keys(self):
        """Root response must contain message, status, and documentation link."""
        data = client.get("/").json()
        assert "message" in data
        assert "status" in data
        assert data["status"] == "online"
        assert "documentation" in data

    def test_root_json_content_type(self):
        """Root response must be application/json."""
        response = client.get("/")
        assert "application/json" in response.headers["content-type"]


# ──────────────────────────────────────────────
# Health Check Endpoint Tests
# ──────────────────────────────────────────────


class TestHealthEndpoint:
    """Tests for GET /health service health endpoint."""

    def test_health_returns_200(self):
        """Health endpoint must return HTTP 200."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_response_schema(self):
        """Health response must contain status, service, artifacts_loaded, model_version."""
        data = client.get("/health").json()
        assert data["status"] == "healthy"
        assert "service" in data
        assert "artifacts_loaded" in data
        assert isinstance(data["artifacts_loaded"], bool)
        assert "model_version" in data

    def test_health_service_name(self):
        """Health endpoint must report 'AI Prediction Engine' as service name."""
        data = client.get("/health").json()
        assert data["service"] == "AI Prediction Engine"


# ──────────────────────────────────────────────
# Single Prediction Endpoint Tests
# ──────────────────────────────────────────────


class TestPredictEndpoint:
    """Tests for POST /predict single event prediction."""

    def test_predict_malicious_event(self):
        """Brute force event should return prediction=1 (Malicious)."""
        payload = {
            "scenario_id": "test_bf",
            "EventID": 4625,
            "failed_login_count_5m": 8.0,
            "is_powershell_executed": 1,
            "privilege_escalation_flag": 1,
        }
        response = client.post("/predict", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["prediction"] == 1
        assert data["confidence"] > 0.0

    def test_predict_benign_event(self):
        """Normal login event should return prediction=0 (Benign)."""
        payload = {
            "scenario_id": "test_benign",
            "EventID": 4624,
            "failed_login_count_5m": 0.0,
            "is_powershell_executed": 0,
            "privilege_escalation_flag": 0,
        }
        response = client.post("/predict", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["prediction"] == 0

    def test_predict_response_has_shap_values(self):
        """Prediction response must include SHAP feature weights."""
        payload = {"EventID": 4625, "failed_login_count_5m": 5.0}
        response = client.post("/predict", json=payload)
        data = response.json()
        assert "shap_values" in data
        assert isinstance(data["shap_values"], dict)

    def test_predict_response_has_model_version(self):
        """Prediction response must include model_version string."""
        payload = {"EventID": 4624}
        response = client.post("/predict", json=payload)
        data = response.json()
        assert "model_version" in data
        assert isinstance(data["model_version"], str)

    def test_predict_confidence_range(self):
        """Confidence score must be between 0.0 and 1.0."""
        payload = {"EventID": 4625, "failed_login_count_5m": 5.0, "is_powershell_executed": 1}
        response = client.post("/predict", json=payload)
        data = response.json()
        assert 0.0 <= data["confidence"] <= 1.0

    def test_predict_with_defaults(self):
        """Predict should work with all default field values."""
        response = client.post("/predict", json={})
        assert response.status_code == 200
        data = response.json()
        assert "prediction" in data

    def test_predict_invalid_body_returns_422(self):
        """Completely invalid JSON body should return 422 Unprocessable Entity."""
        response = client.post("/predict", json="not_a_dict")
        assert response.status_code == 422


# ──────────────────────────────────────────────
# Batch Prediction Endpoint Tests
# ──────────────────────────────────────────────


class TestBatchPredictEndpoint:
    """Tests for POST /predict/batch batch inference."""

    def test_batch_two_events(self):
        """Batch of 2 events should return count=2 and 2 predictions."""
        payload = [
            {"EventID": 4624, "failed_login_count_5m": 0.0},
            {"EventID": 4625, "failed_login_count_5m": 8.0, "is_powershell_executed": 1},
        ]
        response = client.post("/predict/batch", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 2
        assert len(data["predictions"]) == 2

    def test_batch_single_event(self):
        """Batch of 1 event should still work correctly."""
        payload = [{"EventID": 4624}]
        response = client.post("/predict/batch", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 1

    def test_batch_each_prediction_has_required_fields(self):
        """Each prediction in a batch must have prediction, confidence, shap_values."""
        payload = [
            {"EventID": 4625, "failed_login_count_5m": 6.0},
            {"EventID": 4672, "privilege_escalation_flag": 1},
        ]
        response = client.post("/predict/batch", json=payload)
        data = response.json()
        for pred in data["predictions"]:
            assert "prediction" in pred
            assert "confidence" in pred
            assert "shap_values" in pred

    def test_batch_mixed_benign_and_malicious(self):
        """Batch should handle a mix of benign and malicious events."""
        payload = [
            {
                "EventID": 4624,
                "failed_login_count_5m": 0.0,
                "is_powershell_executed": 0,
                "privilege_escalation_flag": 0,
            },
            {
                "EventID": 4625,
                "failed_login_count_5m": 10.0,
                "is_powershell_executed": 1,
                "privilege_escalation_flag": 1,
            },
        ]
        response = client.post("/predict/batch", json=payload)
        data = response.json()
        predictions = [p["prediction"] for p in data["predictions"]]
        assert 0 in predictions
        assert 1 in predictions


# ──────────────────────────────────────────────
# Swagger/OpenAPI Docs Endpoint Tests
# ──────────────────────────────────────────────


class TestDocsEndpoint:
    """Tests for auto-generated FastAPI documentation endpoints."""

    def test_swagger_ui_available(self):
        """Swagger UI at /docs must return HTTP 200."""
        response = client.get("/docs")
        assert response.status_code == 200

    def test_openapi_json_available(self):
        """OpenAPI JSON schema at /openapi.json must return HTTP 200."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
        assert "paths" in data


# ──────────────────────────────────────────────
# Error Handling & Edge Cases
# ──────────────────────────────────────────────


class TestErrorHandling:
    """Tests for error handling and invalid requests."""

    def test_nonexistent_route_returns_404(self):
        """A non-existent route should return 404."""
        response = client.get("/nonexistent_endpoint")
        assert response.status_code == 404

    def test_post_to_health_returns_405(self):
        """POST to /health should return 405 Method Not Allowed."""
        response = client.post("/health")
        assert response.status_code == 405

    def test_get_to_predict_returns_405(self):
        """GET to /predict should return 405 Method Not Allowed."""
        response = client.get("/predict")
        assert response.status_code == 405
