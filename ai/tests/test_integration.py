"""End-to-End Integration Test Suite.

Tests the complete workflow from raw event ingestion through
every processing layer to final intelligence package output:
  Event -> Prediction -> SHAP -> Security Intel -> Correlation -> Risk -> MITRE -> Timeline
"""

import pytest

from ai.correlation.event_correlator import EventCorrelator
from ai.correlation.risk_engine import DynamicRiskEngine
from ai.correlation.timeline_builder import TimelineBuilder
from ai.detection.hybrid_engine import HybridDetectionEngine
from ai.detection.rule_engine import RuleEngine
from ai.detection.simulation import SimulationEngine
from ai.explainability.security_intel import SecurityIntelligenceLayer
from ai.explainability.shap_explainer import ShapExplainer
from ai.mitre.mapper import MitreMapper
from ai.prediction.service import PredictionService

# ──────────────────────────────────────────────
# Full Pipeline Integration Tests
# ──────────────────────────────────────────────


class TestFullPipelineIntegration:
    """End-to-end test from raw event to final intelligence package."""

    def test_brute_force_full_pipeline(self):
        """Complete brute force attack pipeline: event -> predict -> SHAP -> intel -> correlate -> risk -> MITRE."""
        # Step 1: Raw event
        event = {
            "scenario_id": "e2e_brute_force",
            "EventID": 4625,
            "Computer": "DC-01",
            "TargetUserName": "administrator",
            "failed_login_count_5m": 8.0,
            "is_powershell_executed": 0,
            "privilege_escalation_flag": 0,
            "unusual_process_parent_ratio": 0.0,
            "session_duration": 5.0,
        }

        # Step 2: AI Prediction
        pred_service = PredictionService()
        prediction = pred_service.predict_single(event)
        assert prediction["prediction"] == 1
        assert prediction["confidence"] > 0.0
        assert "shap_values" in prediction

        # Step 3: SHAP Explainability
        explainer = ShapExplainer()
        shap_weights = explainer.explain_local_event(event)
        assert shap_weights["failed_login_count_5m"] > 0

        # Step 4: Hybrid Detection
        hybrid = HybridDetectionEngine()
        alert = hybrid.process_event(event)
        assert alert["is_alert"] is True
        assert alert["severity"] in ["Medium", "High", "Critical"]

        # Step 5: Security Intelligence Layer
        intel = SecurityIntelligenceLayer()
        pkg = intel.generate_intelligence_package(alert, shap_weights)
        assert "threat_summary" in pkg
        assert "human_readable_explanation" in pkg
        assert "evidence_package" in pkg
        assert "investigation_recommendations" in pkg
        assert len(pkg["investigation_recommendations"]) >= 3

        # Step 6: Event Correlation
        correlator = EventCorrelator()
        corr_result = correlator.correlate_event(alert)
        assert "incident_id" in corr_result
        assert corr_result["chain_length"] >= 1

        # Step 7: Dynamic Risk Scoring
        risk_engine = DynamicRiskEngine()
        risk = risk_engine.calculate_risk_score(alert, chain_length=corr_result["chain_length"])
        assert 0 <= risk["score"] <= 100
        assert risk["level"] in ["Low", "Medium", "High", "Critical"]
        assert "breakdown" in risk

        # Step 8: MITRE ATT&CK Mapping
        mapper = MitreMapper()
        mitre = mapper.map_event_to_mitre(alert)
        assert len(mitre) > 0
        assert any(m["technique_id"] == "T1110" for m in mitre)

    def test_powershell_attack_full_pipeline(self):
        """Complete suspicious PowerShell pipeline through all layers."""
        event = {
            "scenario_id": "e2e_powershell",
            "EventID": 4688,
            "Computer": "WORKSTATION-03",
            "TargetUserName": "jdoe",
            "ProcessName": "powershell.exe",
            "CommandLine": "powershell -ExecutionPolicy Bypass -encodedcommand SQBFA...",
            "failed_login_count_5m": 0.0,
            "is_powershell_executed": 1,
            "privilege_escalation_flag": 0,
        }

        pred_service = PredictionService()
        prediction = pred_service.predict_single(event)
        assert prediction["prediction"] == 1

        hybrid = HybridDetectionEngine()
        alert = hybrid.process_event(event)
        assert alert["is_alert"] is True

        intel = SecurityIntelligenceLayer()
        explainer = ShapExplainer()
        shap_weights = explainer.explain_local_event(event)
        pkg = intel.generate_intelligence_package(alert, shap_weights)
        assert "PowerShell" in pkg["human_readable_explanation"]

        mapper = MitreMapper()
        mitre = mapper.map_event_to_mitre(alert)
        assert any(m["technique_id"] == "T1059.001" for m in mitre)

    def test_privilege_escalation_full_pipeline(self):
        """Complete privilege escalation pipeline through all layers."""
        event = {
            "scenario_id": "e2e_privesc",
            "EventID": 4672,
            "Computer": "DC-01",
            "TargetUserName": "svc_account",
            "ProcessName": "lsass.exe",
            "failed_login_count_5m": 0.0,
            "is_powershell_executed": 0,
            "privilege_escalation_flag": 1,
        }

        pred_service = PredictionService()
        prediction = pred_service.predict_single(event)
        assert prediction["prediction"] == 1

        hybrid = HybridDetectionEngine()
        alert = hybrid.process_event(event)
        assert alert["is_alert"] is True

        mapper = MitreMapper()
        mitre = mapper.map_event_to_mitre(alert)
        assert any(m["technique_id"] == "T1078" for m in mitre)


# ──────────────────────────────────────────────
# Multi-Stage Attack Chain Integration
# ──────────────────────────────────────────────


class TestMultiStageAttackChain:
    """Test multi-event correlation forming attack chains."""

    def test_three_stage_attack_chain(self):
        """Simulate 3-stage attack: Failed Login -> Success -> Priv Esc."""
        correlator = EventCorrelator()
        timeline = TimelineBuilder()
        risk_engine = DynamicRiskEngine()

        events = [
            {
                "severity": "High",
                "confidence": 0.85,
                "event_id": 4625,
                "triggered_rules": [{"rule_id": "r1"}],
                "raw_event": {"EventID": 4625, "Computer": "HOST-A", "TargetUserName": "admin"},
            },
            {
                "severity": "Medium",
                "confidence": 0.70,
                "event_id": 4624,
                "triggered_rules": [],
                "raw_event": {"EventID": 4624, "Computer": "HOST-A", "TargetUserName": "admin"},
            },
            {
                "severity": "Critical",
                "confidence": 0.95,
                "event_id": 4672,
                "triggered_rules": [{"rule_id": "r2"}, {"rule_id": "r3"}],
                "raw_event": {"EventID": 4672, "Computer": "HOST-A", "TargetUserName": "admin"},
            },
        ]

        results = []
        for evt in events:
            results.append(correlator.correlate_event(evt))

        # Same incident for all 3 events
        assert results[0]["incident_id"] == results[2]["incident_id"]
        assert results[2]["chain_length"] == 3
        assert results[2]["is_multi_stage"] is True

        # Timeline generation
        inc_data = correlator.active_incidents[results[0]["context_key"]]
        nodes = timeline.build_timeline_nodes(inc_data)
        assert len(nodes) == 3
        assert nodes[0]["event_id"] == 4625
        assert nodes[1]["event_id"] == 4624
        assert nodes[2]["event_id"] == 4672

        # Risk score escalates with chain
        risk = risk_engine.calculate_risk_score(events[2], chain_length=3, impacted_hosts_count=1)
        assert risk["score"] > 60
        assert risk["level"] in ["High", "Critical"]

    def test_separate_hosts_create_separate_incidents(self):
        """Events on different hosts should create separate incidents."""
        correlator = EventCorrelator()
        evt1 = {
            "severity": "High",
            "confidence": 0.9,
            "raw_event": {"EventID": 4625, "Computer": "HOST-A", "TargetUserName": "user1"},
        }
        evt2 = {
            "severity": "High",
            "confidence": 0.9,
            "raw_event": {"EventID": 4625, "Computer": "HOST-B", "TargetUserName": "user2"},
        }
        res1 = correlator.correlate_event(evt1)
        res2 = correlator.correlate_event(evt2)
        assert res1["incident_id"] != res2["incident_id"]


# ──────────────────────────────────────────────
# Simulation -> Detection Integration
# ──────────────────────────────────────────────


class TestSimulationIntegration:
    """Test that simulation scenarios trigger proper detections."""

    def test_simulated_brute_force_triggers_alerts(self):
        """All events from FAILED_LOGIN_BURST simulation should trigger alerts."""
        sim = SimulationEngine()
        hybrid = HybridDetectionEngine()

        events = sim.generate_scenario_events("FAILED_LOGIN_BURST")
        assert len(events) == 6

        alerts_raised = 0
        for evt in events:
            alert = hybrid.process_event(evt)
            if alert["is_alert"]:
                alerts_raised += 1

        assert alerts_raised >= 1, "Brute force simulation should trigger at least 1 alert"

    def test_simulated_powershell_triggers_alert(self):
        """SUSPICIOUS_POWERSHELL simulation must trigger at least 1 alert."""
        sim = SimulationEngine()
        hybrid = HybridDetectionEngine()

        events = sim.generate_scenario_events("SUSPICIOUS_POWERSHELL")
        alert = hybrid.process_event(events[0])
        assert alert["is_alert"] is True

    def test_simulated_privesc_triggers_alert(self):
        """PRIVILEGE_ESCALATION simulation must trigger alert."""
        sim = SimulationEngine()
        hybrid = HybridDetectionEngine()

        events = sim.generate_scenario_events("PRIVILEGE_ESCALATION")
        alert = hybrid.process_event(events[0])
        assert alert["is_alert"] is True

    def test_simulated_admin_account_triggers_alert(self):
        """NEW_ADMIN_ACCOUNT simulation must trigger alert."""
        sim = SimulationEngine()
        hybrid = HybridDetectionEngine()

        events = sim.generate_scenario_events("NEW_ADMIN_ACCOUNT")
        for evt in events:
            alert = hybrid.process_event(evt)
            assert alert["is_alert"] is True

    def test_all_simulation_scenarios_return_valid_events(self):
        """Every named scenario must return a non-empty list of valid events."""
        sim = SimulationEngine()
        scenarios = [
            "FAILED_LOGIN_BURST",
            "SUSPICIOUS_POWERSHELL",
            "PRIVILEGE_ESCALATION",
            "NEW_ADMIN_ACCOUNT",
        ]
        for scenario_name in scenarios:
            events = sim.generate_scenario_events(scenario_name)
            assert len(events) > 0, f"Scenario {scenario_name} returned empty events"
            for evt in events:
                assert "EventID" in evt
                assert "scenario_id" in evt
