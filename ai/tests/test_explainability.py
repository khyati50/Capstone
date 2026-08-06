"""Unit Tests for Phase 9 & 10 Explainability & Security Intelligence Layer."""

import pytest
from ai.explainability.shap_explainer import ShapExplainer
from ai.explainability.security_intel import SecurityIntelligenceLayer


def test_shap_explainer_local_attribution():
    """Test local SHAP attribution weight calculation and defensive fallback handling."""
    explainer = ShapExplainer()
    event = {
        "failed_login_count_5m": 5,
        "is_powershell_executed": 1,
        "privilege_escalation_flag": 1,
    }
    weights = explainer.explain_local_event(event)

    assert "failed_login_count_5m" in weights
    assert "is_powershell_executed" in weights
    assert "privilege_escalation_flag" in weights
    assert weights["failed_login_count_5m"] > 0.0

    # Verify defensive fallback when an unsupported model object is provided
    class DummyFaultyModel:
        pass

    faulty_explainer = ShapExplainer(model_obj=DummyFaultyModel())
    fallback_weights = faulty_explainer.explain_local_event(event)
    assert "failed_login_count_5m" in fallback_weights
    assert fallback_weights["failed_login_count_5m"] > 0.0


def test_security_intelligence_layer_generation():
    """Test translation of SHAP weights into human-readable SOC intelligence."""
    intel_layer = SecurityIntelligenceLayer()
    alert_object = {
        "severity": "High",
        "confidence": 0.92,
        "triggered_rules": [{"rule_id": "RULE_BRUTE_FORCE_001"}],
        "raw_event": {
            "EventID": 4625,
            "Computer": "CORP-HOST-01",
            "TargetUserName": "jdoe",
            "failed_login_count_5m": 6,
            "is_powershell_executed": 1,
        },
    }
    shap_values = {
        "failed_login_count_5m": 0.42,
        "is_powershell_executed": 0.38,
    }

    pkg = intel_layer.generate_intelligence_package(alert_object, shap_values)

    assert "threat_summary" in pkg
    assert "human_readable_explanation" in pkg
    assert "evidence_package" in pkg
    assert "investigation_recommendations" in pkg

    assert "CORP-HOST-01" in pkg["threat_summary"]
    assert len(pkg["investigation_recommendations"]) >= 3
