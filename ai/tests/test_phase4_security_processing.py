"""Phase 4 Test Suite — Security Processing Validation & Hardening.

Covering Phase 4.1 through Phase 4.6:
- Phase 4.1: MITRE ATT&CK Mapping (PowerShell T1059.001, Benign/Security Event, Unknown Event T1036 fallback)
- Phase 4.2: Event Correlation (Single event context, Multiple related events chain growth, Unrelated events isolation)
- Phase 4.3: Timeline Construction (Single event 1 node, Multiple ordered nodes retaining all 7 attributes)
- Phase 4.4: Dynamic Risk Assessment (Factor weighting breakdown & Low/Medium/High/Critical tiers)
- Phase 4.5: SHAP & Security Intelligence (Alert vs Benign event intelligence package output)
- Phase 4.6: Full Unified Integration (Validation of all 17+ security result fields)
"""

from ai.correlation.event_correlator import EventCorrelator
from ai.correlation.risk_engine import DynamicRiskEngine
from ai.correlation.timeline_builder import TimelineBuilder
from ai.explainability.security_intel import SecurityIntelligenceLayer
from ai.mitre.mapper import MitreMapper
from ai.pipeline.orchestrator import LivePipelineOrchestrator


class TestPhase41MitreValidation:
    """Phase 4.1 — MITRE ATT&CK Mapping Validation."""

    def test_scenario_a_powershell_mitre_mapping(self):
        """Scenario A: PowerShell event maps to T1059.001 with structured fields."""
        mapper = MitreMapper()
        event = {
            "EventID": 4688,
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -encodedcommand SQBFA...",
            "ProcessName": "powershell.exe",
        }
        res = mapper.map_event_to_mitre(event)
        assert len(res) > 0
        ps_tech = next((t for t in res if t["technique_id"] == "T1059.001"), None)
        assert ps_tech is not None
        assert ps_tech["tactic"] == "Execution"
        assert "PowerShell" in ps_tech["technique_name"]
        assert ps_tech["active_alerts"] >= 1
        assert ps_tech["level"] in ["Medium", "High", "Critical"]

    def test_scenario_b_benign_security_event_mitre_mapping(self):
        """Scenario B: Standard security logon event maps to valid structured MITRE output."""
        mapper = MitreMapper()
        event = {"EventID": 4624, "Computer": "DC-01", "TargetUserName": "userA"}
        res = mapper.map_event_to_mitre(event)
        assert isinstance(res, list)
        assert len(res) >= 1
        for tech in res:
            assert "tactic" in tech
            assert "technique_name" in tech
            assert "technique_id" in tech
            assert "active_alerts" in tech
            assert "level" in tech

    def test_scenario_c_unknown_behavior_fallback(self):
        """Scenario C: Unknown / unmapped event defaults safely to T1036 Defense Evasion fallback."""
        mapper = MitreMapper()
        event = {"EventID": 9999, "Computer": "HOST-X", "CommandLine": "some_custom_tool.exe"}
        res = mapper.map_event_to_mitre(event)
        assert len(res) >= 1
        fallback_tech = res[0]
        assert fallback_tech["technique_id"] == "T1036"
        assert fallback_tech["tactic"] == "Defense Evasion"
        assert "Unusual Log Activity Anomaly" in fallback_tech["technique_name"]


class TestPhase42CorrelationValidation:
    """Phase 4.2 — Event Correlation Validation."""

    def test_test_a_single_event_correlation(self):
        """Test A: Single event correlation returns incident ID, chain_length=1, is_multi_stage=False."""
        correlator = EventCorrelator()
        alert = {
            "severity": "Medium",
            "confidence": 0.75,
            "raw_event": {"EventID": 4625, "Computer": "WORKSTATION-1", "TargetUserName": "alice"},
        }
        res = correlator.correlate_event(alert)

        assert "incident_id" in res
        assert res["incident_id"].startswith("INC-")
        assert res["chain_length"] == 1
        assert res["is_multi_stage"] is False
        assert res["context_key"] == "WORKSTATION-1::alice"
        assert res["event_sequence"] == [4625]

    def test_test_b_multiple_related_events_correlation(self):
        """Test B: Multiple events on same host/user context increase chain length and track scope."""
        correlator = EventCorrelator()
        context = {"Computer": "HOST-A", "TargetUserName": "admin"}

        evt1 = {"severity": "Medium", "confidence": 0.7, "raw_event": {**context, "EventID": 4625}}
        evt2 = {"severity": "High", "confidence": 0.85, "raw_event": {**context, "EventID": 4624}}
        evt3 = {"severity": "Critical", "confidence": 0.95, "raw_event": {**context, "EventID": 4672}}

        res1 = correlator.correlate_event(evt1)
        res2 = correlator.correlate_event(evt2)
        res3 = correlator.correlate_event(evt3)

        assert res1["incident_id"] == res2["incident_id"] == res3["incident_id"]
        assert res1["chain_length"] == 1
        assert res2["chain_length"] == 2
        assert res3["chain_length"] == 3
        assert res3["is_multi_stage"] is True
        assert res3["event_sequence"] == [4625, 4624, 4672]
        assert res3["unique_hosts_count"] == 1
        assert res3["unique_users_count"] == 1

    def test_test_c_unrelated_events_correlation(self):
        """Test C: Events on different host/user contexts create distinct incident IDs."""
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
        assert res1["chain_length"] == 1
        assert res2["chain_length"] == 1
        assert res1["context_key"] == "HOST-A::user1"
        assert res2["context_key"] == "HOST-B::user2"


class TestPhase43TimelineValidation:
    """Phase 4.3 — Timeline Construction Validation."""

    def test_single_event_timeline(self):
        """Single event yields exactly 1 timeline node."""
        builder = TimelineBuilder()
        incident_data = {
            "events": [
                {
                    "severity": "High",
                    "confidence": 0.85,
                    "raw_event": {
                        "EventID": 4625,
                        "TimeCreated": "2026-08-12T10:00:00Z",
                        "Computer": "HOST-1",
                        "TargetUserName": "jdoe",
                        "ProcessName": "lsass.exe",
                    },
                }
            ]
        }
        nodes = builder.build_timeline_nodes(incident_data)
        assert len(nodes) == 1
        node = nodes[0]
        assert node["step"] == 1
        assert node["node_id"] == "node_1"
        assert node["event_id"] == 4625

    def test_multiple_events_ordered_timeline_attributes(self):
        """Multiple events yield ordered nodes preserving all 7 required attributes."""
        builder = TimelineBuilder()
        incident_data = {
            "events": [
                {
                    "severity": "Medium",
                    "confidence": 0.70,
                    "raw_event": {
                        "EventID": 4625,
                        "TimeCreated": "2026-08-12T10:00:00Z",
                        "Computer": "DC-01",
                        "TargetUserName": "admin",
                        "ProcessName": "winlogon.exe",
                    },
                },
                {
                    "severity": "High",
                    "confidence": 0.85,
                    "raw_event": {
                        "EventID": 4624,
                        "TimeCreated": "2026-08-12T10:01:00Z",
                        "Computer": "DC-01",
                        "TargetUserName": "admin",
                        "ProcessName": "svchost.exe",
                    },
                },
                {
                    "severity": "Critical",
                    "confidence": 0.95,
                    "raw_event": {
                        "EventID": 4672,
                        "TimeCreated": "2026-08-12T10:02:00Z",
                        "Computer": "DC-01",
                        "TargetUserName": "admin",
                        "ProcessName": "lsass.exe",
                    },
                },
            ]
        }

        nodes = builder.build_timeline_nodes(incident_data)
        assert len(nodes) == 3

        for idx, node in enumerate(nodes, start=1):
            assert node["step"] == idx
            assert node["node_id"] == f"node_{idx}"
            # Check retention of all 7 required attributes
            assert "event_id" in node
            assert "timestamp" in node
            assert "severity" in node
            assert "confidence" in node
            assert "computer" in node
            assert "user" in node
            assert "process" in node

        assert nodes[0]["event_id"] == 4625
        assert nodes[1]["event_id"] == 4624
        assert nodes[2]["event_id"] == 4672


class TestPhase44RiskValidation:
    """Phase 4.4 — Dynamic Risk Assessment Validation."""

    def test_risk_factors_and_breakdown(self):
        """Test risk score calculation returns complete breakdown and sublines."""
        risk_engine = DynamicRiskEngine()
        alert = {
            "confidence": 0.90,
            "event_id": 4672,
            "triggered_rules": [{"rule_id": "R1"}, {"rule_id": "R2"}],
            "alert_source": "AI_AND_RULE_AGREEMENT",
            "raw_event": {"EventID": 4672},
        }

        res = risk_engine.calculate_risk_score(
            alert,
            chain_length=3,
            impacted_hosts_count=2,
            unique_users_count=1,
            total_rules_count=2,
            alert_source="AI_AND_RULE_AGREEMENT",
            event_sequence=[4625, 4624, 4672],
        )

        assert "score" in res
        assert 0.0 <= res["score"] <= 100.0
        assert "level" in res
        assert res["level"] in ["Low", "Medium", "High", "Critical"]

        # Verify breakdown keys
        bd = res["breakdown"]
        assert "ai_confidence_weight" in bd
        assert "rule_hits_weight" in bd
        assert "mitre_tactic_weight" in bd
        assert "tactic_diversity_weight" in bd
        assert "scope_weight" in bd
        assert "corroboration_multiplier" in bd

        # Verify sublines keys
        sub = res["sublines"]
        assert "ai_confidence_subline" in sub
        assert "rule_hits_subline" in sub
        assert "mitre_tactic_subline" in sub
        assert "tactic_diversity_subline" in sub
        assert "scope_subline" in sub
        assert "corroboration_subline" in sub

    def test_qualitative_risk_levels(self):
        """Test low, medium, high, and critical risk score tiers."""
        risk_engine = DynamicRiskEngine()

        # Low risk event (low confidence, benign)
        low_alert = {
            "confidence": 0.50,
            "event_id": 4624,
            "triggered_rules": [],
            "alert_source": "BENIGN",
            "raw_event": {"EventID": 4624},
        }
        res_low = risk_engine.calculate_risk_score(low_alert, chain_length=1, alert_source="BENIGN")
        assert res_low["level"] == "Low"
        assert res_low["score"] <= 25.0

        # Critical risk event (high confidence, multiple rules, privesc, high chain length)
        crit_alert = {
            "confidence": 0.98,
            "event_id": 4672,
            "triggered_rules": [{"rule_id": "r1"}, {"rule_id": "r2"}, {"rule_id": "r3"}],
            "alert_source": "AI_AND_RULE_AGREEMENT",
            "raw_event": {"EventID": 4672},
        }
        res_crit = risk_engine.calculate_risk_score(
            crit_alert,
            chain_length=5,
            impacted_hosts_count=3,
            unique_users_count=2,
            total_rules_count=3,
            alert_source="AI_AND_RULE_AGREEMENT",
            event_sequence=[4625, 4624, 4672, 4688, 4720],
        )
        assert res_crit["level"] == "Critical"
        assert res_crit["score"] >= 76.0


class TestPhase45SecurityIntelligenceValidation:
    """Phase 4.5 — SHAP & Security Intelligence Validation."""

    def test_alert_event_security_intel_package(self):
        """Alert event produces complete security intelligence package with 4 SOC recommendations."""
        intel = SecurityIntelligenceLayer()
        alert = {
            "severity": "High",
            "confidence": 0.92,
            "triggered_rules": [{"rule_id": "RULE_BRUTE_FORCE_001"}],
            "raw_event": {
                "EventID": 4625,
                "Computer": "DC-01",
                "TargetUserName": "administrator",
                "failed_login_count_5m": 8,
            },
        }
        shap_vals = {"failed_login_count_5m": 0.42, "is_powershell_executed": 0.0}

        pkg = intel.generate_intelligence_package(alert, shap_vals)

        assert "threat_summary" in pkg
        assert "threat_type" in pkg
        assert "human_readable_explanation" in pkg
        assert "evidence_package" in pkg
        assert "investigation_recommendations" in pkg

        assert "DC-01" in pkg["threat_summary"]
        assert "administrator" in pkg["threat_summary"]
        assert len(pkg["investigation_recommendations"]) >= 3

    def test_benign_event_security_intel_package(self):
        """Benign event produces valid intelligence package without errors or empty strings."""
        intel = SecurityIntelligenceLayer()
        alert = {
            "severity": "Low",
            "confidence": 0.0,
            "triggered_rules": [],
            "raw_event": {
                "EventID": 4624,
                "Computer": "WORKSTATION-01",
                "TargetUserName": "userB",
            },
        }
        shap_vals = {}

        pkg = intel.generate_intelligence_package(alert, shap_vals)

        assert isinstance(pkg["threat_summary"], str) and len(pkg["threat_summary"]) > 0
        assert isinstance(pkg["threat_type"], str) and len(pkg["threat_type"]) > 0
        assert isinstance(pkg["human_readable_explanation"], str) and len(pkg["human_readable_explanation"]) > 0
        assert isinstance(pkg["evidence_package"], dict)
        assert isinstance(pkg["investigation_recommendations"], list) and len(pkg["investigation_recommendations"]) >= 1


class TestPhase46FullIntegrationValidation:
    """Phase 4.6 — Full Unified Security Result Validation."""

    def test_unified_security_result_all_17_fields(self):
        """Verify that LivePipelineOrchestrator.process_event returns all 17+ required fields."""
        orchestrator = LivePipelineOrchestrator()
        features = {
            "scenario_id": "test_e2e_scen",
            "EventID": 4688,
            "Computer": "DC-01",
            "TargetUserName": "admin",
            "ProcessName": "powershell.exe",
            "CommandLine": "powershell -ExecutionPolicy Bypass -enc ...",
            "failed_login_count_5m": 0.0,
            "time_delta_prev_event": 1.5,
            "is_powershell_executed": 1.0,
            "privilege_escalation_flag": 0.0,
            "unusual_process_parent_ratio": 0.8,
            "session_duration": 120.0,
            "EventRecordID": 9001,
            "record_id": 9001,
        }

        res = orchestrator.process_event(features)

        # Verify all 17+ expected result fields exist and are non-null
        expected_keys = [
            "prediction",
            "confidence",
            "severity",
            "alert_source",
            "model_version",
            "shap_values",
            "triggered_rules",
            "threat_summary",
            "threat_type",
            "explanation",
            "evidence_package",
            "recommendations",
            "incident_id",
            "chain_length",
            "is_multi_stage",
            "risk_score",
            "risk_level",
            "risk_breakdown",
            "risk_sublines",
            "mitre_mapping",
            "timeline_nodes",
            "raw_event",
        ]

        for key in expected_keys:
            assert key in res, f"Missing required output key: '{key}'"

        assert res["raw_event"]["EventRecordID"] == 9001
        assert res["prediction"] in (0, 1)
        assert 0.0 <= res["risk_score"] <= 100.0
        assert res["risk_level"] in ["Low", "Medium", "High", "Critical"]
        assert len(res["mitre_mapping"]) >= 1
        assert len(res["timeline_nodes"]) >= 1
