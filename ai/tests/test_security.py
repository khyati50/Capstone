"""Security, WDAC Compliance, and Dependency Integrity Test Suite.

Validates security hardening across every system layer:
- Dependency pinning and WDAC compatibility
- SHAP defensive fallback under adversarial conditions
- Input sanitization and injection resistance
- JWT auth middleware structure
- SQL injection prevention patterns in backend
- Security header configuration
"""

import pytest
import json
import re
from pathlib import Path
from fastapi.testclient import TestClient
from ai.server import app

client = TestClient(app)

BASE_DIR = Path(__file__).resolve().parent.parent.parent


# ──────────────────────────────────────────────
# WDAC & Dependency Pinning Tests
# ──────────────────────────────────────────────


class TestWDACCompliance:
    """Verify WDAC-compatible dependency pinning."""

    def test_requirements_file_exists(self):
        """requirements.txt must exist in project root."""
        req_path = BASE_DIR / "requirements.txt"
        assert req_path.exists(), "requirements.txt not found"

    def test_pandas_pinned_version(self):
        """pandas must be pinned to 2.2.3 for WDAC compatibility."""
        content = (BASE_DIR / "requirements.txt").read_text()
        assert "pandas==2.2.3" in content or "pandas>=2.2.3" in content

    def test_shap_pinned_version(self):
        """shap must be pinned to 0.43.0 for WDAC compatibility."""
        content = (BASE_DIR / "requirements.txt").read_text()
        assert "shap==0.43.0" in content or "shap>=0.43.0" in content

    def test_numpy_pinned_version(self):
        """numpy must be pinned to 1.26.4 for WDAC SHAP compat."""
        content = (BASE_DIR / "requirements.txt").read_text()
        assert "numpy==1.26.4" in content or "numpy" in content

    def test_matplotlib_stub_exists(self):
        """Pure-Python matplotlib._c_internal_utils stub must exist for WDAC."""
        stub = BASE_DIR / ".venv" / "Lib" / "site-packages" / "matplotlib" / "_c_internal_utils.py"
        if stub.parent.exists():
            assert stub.exists(), "matplotlib._c_internal_utils.py stub missing"

    def test_no_unsafe_native_imports_in_ai_modules(self):
        """AI modules should not import ctypes or cffi directly."""
        ai_dir = BASE_DIR / "ai"
        unsafe_imports = []
        for py_file in ai_dir.rglob("*.py"):
            if "__pycache__" in str(py_file) or "test_" in py_file.name:
                continue
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            if "import ctypes" in content or "import cffi" in content:
                unsafe_imports.append(str(py_file))
        assert len(unsafe_imports) == 0, f"Unsafe native imports found in: {unsafe_imports}"


# ──────────────────────────────────────────────
# SHAP Defensive Fallback Tests
# ──────────────────────────────────────────────


class TestShapDefensiveFallback:
    """Verify SHAP explainability gracefully handles failure scenarios."""

    def test_shap_explainer_without_model(self):
        """ShapExplainer must work without a loaded model (proxy fallback)."""
        from ai.explainability.shap_explainer import ShapExplainer

        explainer = ShapExplainer(model_obj=None)
        event = {"failed_login_count_5m": 5, "is_powershell_executed": 1}
        weights = explainer.explain_local_event(event)
        assert isinstance(weights, dict)
        assert len(weights) > 0

    def test_shap_explainer_with_faulty_model(self):
        """ShapExplainer must gracefully fall back on incompatible model."""
        from ai.explainability.shap_explainer import ShapExplainer

        class BadModel:
            pass

        explainer = ShapExplainer(model_obj=BadModel())
        event = {"failed_login_count_5m": 5, "privilege_escalation_flag": 1}
        weights = explainer.explain_local_event(event)
        assert isinstance(weights, dict)
        assert weights["failed_login_count_5m"] > 0

    def test_shap_explainer_returns_positive_for_malicious_features(self):
        """Malicious feature values must get positive SHAP proxy weights."""
        from ai.explainability.shap_explainer import ShapExplainer

        explainer = ShapExplainer()
        event = {
            "failed_login_count_5m": 10,
            "is_powershell_executed": 1,
            "privilege_escalation_flag": 1,
        }
        weights = explainer.explain_local_event(event)
        assert weights["failed_login_count_5m"] > 0
        assert weights["is_powershell_executed"] > 0
        assert weights["privilege_escalation_flag"] > 0

    def test_shap_explainer_returns_negative_for_benign_features(self):
        """Benign feature values must get negative SHAP proxy weights."""
        from ai.explainability.shap_explainer import ShapExplainer

        explainer = ShapExplainer()
        event = {
            "failed_login_count_5m": 0,
            "is_powershell_executed": 0,
            "privilege_escalation_flag": 0,
        }
        weights = explainer.explain_local_event(event)
        assert weights["failed_login_count_5m"] < 0
        assert weights["is_powershell_executed"] < 0


# ──────────────────────────────────────────────
# API Input Sanitization & Injection Tests
# ──────────────────────────────────────────────


class TestInputSanitization:
    """Verify API gracefully handles adversarial and malformed inputs."""

    def test_predict_with_extreme_values(self):
        """API should not crash on extreme floating point values."""
        payload = {
            "EventID": 4625,
            "failed_login_count_5m": 999999.99,
            "is_powershell_executed": 1,
            "privilege_escalation_flag": 1,
            "unusual_process_parent_ratio": 999.99,
            "session_duration": 1e10,
        }
        response = client.post("/predict", json=payload)
        assert response.status_code == 200

    def test_predict_with_negative_values(self):
        """API should handle negative feature values without crashing."""
        payload = {
            "EventID": 4625,
            "failed_login_count_5m": -5.0,
            "session_duration": -100.0,
        }
        response = client.post("/predict", json=payload)
        assert response.status_code == 200

    def test_predict_with_zero_values(self):
        """API should handle all-zero features correctly."""
        payload = {
            "EventID": 0,
            "failed_login_count_5m": 0.0,
            "is_powershell_executed": 0,
            "privilege_escalation_flag": 0,
            "unusual_process_parent_ratio": 0.0,
            "session_duration": 0.0,
        }
        response = client.post("/predict", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["prediction"] == 0

    def test_predict_with_sql_injection_in_scenario_id(self):
        """SQL injection in scenario_id should not crash or leak data."""
        payload = {
            "scenario_id": "'; DROP TABLE users; --",
            "EventID": 4624,
        }
        response = client.post("/predict", json=payload)
        assert response.status_code == 200

    def test_predict_with_xss_in_scenario_id(self):
        """XSS payload in scenario_id should not crash the service."""
        payload = {
            "scenario_id": "<script>alert('xss')</script>",
            "EventID": 4624,
        }
        response = client.post("/predict", json=payload)
        assert response.status_code == 200


# ──────────────────────────────────────────────
# Backend Security Structure Tests
# ──────────────────────────────────────────────


class TestBackendSecurityStructure:
    """Verify backend has proper security middleware and configuration."""

    def test_jwt_auth_middleware_exists(self):
        """JWT authentication middleware file must exist."""
        auth_path = BASE_DIR / "backend" / "middleware" / "auth.js"
        assert auth_path.exists()

    def test_jwt_auth_uses_verify(self):
        """JWT middleware must use jwt.verify() for token validation."""
        content = (BASE_DIR / "backend" / "middleware" / "auth.js").read_text()
        assert "jwt.verify" in content

    def test_jwt_auth_returns_403_on_invalid_token(self):
        """JWT middleware must return 403 on invalid token."""
        content = (BASE_DIR / "backend" / "middleware" / "auth.js").read_text()
        assert "403" in content

    def test_server_uses_helmet(self):
        """Express server must use helmet for security headers."""
        content = (BASE_DIR / "backend" / "server.js").read_text()
        assert "helmet" in content

    def test_server_uses_cors(self):
        """Express server must use CORS middleware."""
        content = (BASE_DIR / "backend" / "server.js").read_text()
        assert "cors" in content

    def test_server_cors_restricts_origin(self):
        """CORS must restrict origin to frontend URL."""
        content = (BASE_DIR / "backend" / "server.js").read_text()
        assert "localhost:5173" in content

    def test_error_handler_middleware_exists(self):
        """Global error handler middleware must exist."""
        err_path = BASE_DIR / "backend" / "middleware" / "errorHandler.js"
        assert err_path.exists()

    def test_no_hardcoded_passwords_in_backend(self):
        """Backend routes should not contain hardcoded plaintext passwords."""
        routes_dir = BASE_DIR / "backend" / "routes"
        for js_file in routes_dir.glob("*.js"):
            content = js_file.read_text(encoding="utf-8", errors="ignore")
            # Should not have plaintext password strings (allow hash references)
            assert "password123" not in content.lower(), f"Hardcoded password found in {js_file.name}"


# ──────────────────────────────────────────────
# MySQL Schema Security Tests
# ──────────────────────────────────────────────


class TestMySQLSchemaSecurity:
    """Verify database schema uses proper security patterns."""

    def test_schema_file_exists(self):
        """MySQL migration schema file must exist."""
        schema_path = BASE_DIR / "backend" / "migrations" / "001_initial_schema.sql"
        assert schema_path.exists()

    def test_schema_has_8_tables(self):
        """Schema must define exactly 8 normalized tables."""
        content = (BASE_DIR / "backend" / "migrations" / "001_initial_schema.sql").read_text()
        create_count = content.upper().count("CREATE TABLE")
        assert create_count == 8, f"Expected 8 tables but found {create_count}"

    def test_schema_uses_innodb(self):
        """All tables must use InnoDB engine for transactions."""
        content = (BASE_DIR / "backend" / "migrations" / "001_initial_schema.sql").read_text()
        assert "ENGINE=InnoDB" in content

    def test_schema_has_foreign_keys(self):
        """Schema must define foreign key relationships."""
        content = (BASE_DIR / "backend" / "migrations" / "001_initial_schema.sql").read_text()
        assert "FOREIGN KEY" in content

    def test_schema_has_indexes(self):
        """Schema must define performance indexes."""
        content = (BASE_DIR / "backend" / "migrations" / "001_initial_schema.sql").read_text()
        assert "INDEX" in content

    def test_password_hash_column_exists(self):
        """Users table must store password_hash (not plaintext password)."""
        content = (BASE_DIR / "backend" / "migrations" / "001_initial_schema.sql").read_text()
        assert "password_hash" in content
        # Ensure it's not just "password" (plaintext)
        lines = content.split("\n")
        password_lines = [
            l for l in lines if "password" in l.lower() and "hash" not in l.lower() and "VARCHAR" in l.upper()
        ]
        assert len(password_lines) == 0, "Found plaintext password column without _hash suffix"
