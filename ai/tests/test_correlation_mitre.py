"""Unit Tests for Phases 11, 12, 13 Correlation, Risk Engine, and MITRE Mapping."""

import pytest
from ai.correlation.event_correlator import EventCorrelator
from ai.correlation.timeline_builder import TimelineBuilder
from ai.correlation.risk_engine import DynamicRiskEngine
from ai.mitre.mapper import MitreMapper


def test_event_correlator_and_timeline():
    """Test correlation of multiple events into incident timeline."""
    correlator = EventCorrelator()
    builder = TimelineBuilder()

    evt1 = {
        "severity": "Medium",
        "confidence": 0.8,
        "raw_event": {"EventID": 4625, "Computer": "HOST-01", "TargetUserName": "userA"},
    }
    evt2 = {
        "severity": "High",
        "confidence": 0.9,
        "raw_event": {"EventID": 4672, "Computer": "HOST-01", "TargetUserName": "userA"},
    }

    res1 = correlator.correlate_event(evt1)
    res2 = correlator.correlate_event(evt2)

    assert res1["incident_id"] == res2["incident_id"]
    assert res2["chain_length"] == 2
    assert res2["is_multi_stage"] is True

    inc_data = correlator.active_incidents[res2["context_key"]]
    nodes = builder.build_timeline_nodes(inc_data)

    assert len(nodes) == 2
    assert nodes[0]["event_id"] == 4625
    assert nodes[1]["event_id"] == 4672


def test_dynamic_risk_engine():
    """Test dynamic risk scoring formula and qualitative levels."""
    risk_engine = DynamicRiskEngine()

    alert_critical = {
        "confidence": 0.95,
        "event_id": 4672,
        "triggered_rules": [{"rule_id": "r1"}, {"rule_id": "r2"}],
    }

    res = risk_engine.calculate_risk_score(alert_critical, chain_length=3, impacted_hosts_count=2)

    assert "score" in res
    assert "level" in res
    assert res["score"] > 50.0
    assert res["level"] in ["High", "Critical"]


def test_mitre_mapper():
    """Test Event ID and PowerShell mapping to MITRE ATT&CK techniques."""
    mapper = MitreMapper()

    mapped_bf = mapper.map_event_to_mitre({"EventID": 4625})
    assert len(mapped_bf) > 0
    assert mapped_bf[0]["technique_id"] == "T1110"

    mapped_ps = mapper.map_event_to_mitre({"EventID": 4688, "CommandLine": "powershell -enc ..."})
    assert any(m["technique_id"] == "T1059.001" for m in mapped_ps)
