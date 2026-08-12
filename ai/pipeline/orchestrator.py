"""AI Threat Detection Pipeline Orchestrator.

Establishes the clean execution boundary between real-time event ingestion
and the existing downstream AI threat detection pipeline components.

Phase 3 — AI / Feature Engineering Integration
"""

from typing import Any, Dict

from ai.correlation.event_correlator import EventCorrelator
from ai.correlation.risk_engine import DynamicRiskEngine
from ai.correlation.timeline_builder import TimelineBuilder
from ai.detection.hybrid_engine import HybridDetectionEngine
from ai.explainability.security_intel import SecurityIntelligenceLayer
from ai.mitre.mapper import MitreMapper
from ai.prediction.service import PredictionService


class LivePipelineOrchestrator:
    """Stateful orchestrator for executing full AI threat detection on normalized event features."""

    def __init__(
        self,
        prediction_service: PredictionService = None,
        hybrid_engine: HybridDetectionEngine = None,
        security_intel: SecurityIntelligenceLayer = None,
        risk_engine: DynamicRiskEngine = None,
        mitre_mapper: MitreMapper = None,
        event_correlator: EventCorrelator = None,
        timeline_builder: TimelineBuilder = None,
    ) -> None:
        """Initialize LivePipelineOrchestrator with singletons or provided component instances."""
        self.prediction_service = prediction_service or PredictionService()
        self.hybrid_engine = hybrid_engine or HybridDetectionEngine(self.prediction_service)
        self.security_intel = security_intel or SecurityIntelligenceLayer()
        self.risk_engine = risk_engine or DynamicRiskEngine()
        self.mitre_mapper = mitre_mapper or MitreMapper()
        self.event_correlator = event_correlator or EventCorrelator()
        self.timeline_builder = timeline_builder or TimelineBuilder()

    def process_event(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Execute complete end-to-end AI security pipeline on a single log event feature dictionary.

        Args:
            features: Dictionary containing normalized event parameters and computed behavioral features.

        Returns:
            Unified security intelligence and threat assessment dictionary.
        """
        # 1. Hybrid Detection (ML + Signature Rules)
        alert_obj = self.hybrid_engine.process_event(features)

        # 2. SHAP & Security Intelligence Synthesis
        shap_vals = alert_obj.get("shap_values", {})
        intel_pkg = self.security_intel.generate_intelligence_package(alert_obj, shap_vals)

        # 3. Correlation Engine & Timeline Graph Construction
        corr_res = self.event_correlator.correlate_event(alert_obj)
        context_key = corr_res["context_key"]
        incident_data = self.event_correlator.active_incidents.get(context_key, {})
        incident_evts = corr_res.get("incident_events", incident_data.get("events", []))
        timeline_nodes = self.timeline_builder.build_timeline_nodes(incident_evts)

        # 4. MITRE ATT&CK Mapping (Run before risk assessment so techniques feed into risk engine)
        mitre_res = self.mitre_mapper.map_event_to_mitre(alert_obj)

        # 5. Cumulative Multi-Factor Dynamic Risk Assessment (Final Spec Formula)
        total_rules = corr_res.get("total_rules", [])
        total_rules_count = len(total_rules)
        unique_hosts_count = corr_res.get("unique_hosts_count", 1)
        unique_users_count = corr_res.get("unique_users_count", 1)
        event_sequence = corr_res.get("event_sequence", [])

        risk_res = self.risk_engine.calculate_risk_score(
            alert_obj,
            chain_length=corr_res["chain_length"],
            impacted_hosts_count=unique_hosts_count,
            unique_users_count=unique_users_count,
            total_rules_count=total_rules_count,
            mitre_techniques=mitre_res,
            alert_source=alert_obj.get("alert_source", "AI_ANOMALY_ONLY"),
            event_sequence=event_sequence,
        )

        return {
            "prediction": 1 if alert_obj["is_alert"] else 0,
            "confidence": alert_obj["confidence"],
            "severity": alert_obj["severity"],
            "alert_source": alert_obj["alert_source"],
            "model_version": alert_obj.get("model_version", "v1.0.0"),
            "shap_values": shap_vals,
            "triggered_rules": alert_obj["triggered_rules"],
            "threat_summary": intel_pkg["threat_summary"],
            "threat_type": intel_pkg["threat_type"],
            "explanation": intel_pkg["human_readable_explanation"],
            "evidence_package": intel_pkg["evidence_package"],
            "recommendations": intel_pkg["investigation_recommendations"],
            "incident_id": corr_res["incident_id"],
            "chain_length": corr_res["chain_length"],
            "is_multi_stage": corr_res["is_multi_stage"],
            "risk_score": risk_res["score"],
            "risk_level": risk_res["level"],
            "risk_breakdown": risk_res["breakdown"],
            "risk_sublines": risk_res.get("sublines", {}),
            "mitre_mapping": mitre_res,
            "timeline_nodes": timeline_nodes,
            "raw_event": features,
        }

    def reset_state(self) -> None:
        """Reset stateful components (correlator and MITRE mapper)."""
        self.event_correlator.reset()
        self.mitre_mapper.reset()
