"""Unit Tests for Phase 7 & 8 Detection Engine and Simulation Module."""

import pytest
from ai.detection.rule_engine import RuleEngine
from ai.detection.hybrid_engine import HybridDetectionEngine
from ai.detection.simulation import SimulationEngine


def test_rule_engine_evaluation():
    """Test rule engine detection logic."""
    engine = RuleEngine()

    # Test brute force rule
    event_bf = {"EventID": 4625, "failed_login_count_5m": 6}
    rules_bf = engine.evaluate_rules(event_bf)
    assert len(rules_bf) > 0
    assert any(r["rule_id"] == "RULE_BRUTE_FORCE_001" for r in rules_bf)

    # Test suspicious powershell rule
    event_ps = {"EventID": 4688, "CommandLine": "powershell -ExecutionPolicy Bypass"}
    rules_ps = engine.evaluate_rules(event_ps)
    assert len(rules_ps) > 0
    assert any(r["rule_id"] == "RULE_POWERSHELL_SUSPICIOUS_002" for r in rules_ps)


def test_hybrid_engine_fusion():
    """Test hybrid detection engine decision fusion."""
    hybrid = HybridDetectionEngine()

    # Event matching both AI anomaly and Rule engine
    event = {
        "scenario_id": "test_fusion",
        "EventID": 4625,
        "failed_login_count_5m": 6,
        "is_powershell_executed": 1,
        "privilege_escalation_flag": 1,
    }

    alert = hybrid.process_event(event)
    assert alert["is_alert"] is True
    assert alert["alert_source"] in ["AI_AND_RULE_AGREEMENT", "AI_ANOMALY_ONLY", "RULE_SIGNATURE_ONLY"]
    assert alert["severity"] in ["High", "Critical"]


def test_simulation_engine_scenarios():
    """Test attack simulation engine sequence generation."""
    sim = SimulationEngine()

    bf_events = sim.generate_scenario_events("FAILED_LOGIN_BURST")
    assert len(bf_events) == 6
    assert bf_events[0]["EventID"] == 4625

    ps_events = sim.generate_scenario_events("SUSPICIOUS_POWERSHELL")
    assert len(ps_events) == 1
    assert ps_events[0]["is_powershell_executed"] == 1
