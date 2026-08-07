"""FastAPI Prediction Service Application Server.

Runs AI prediction microservice on port 8000.
Endpoints:
  GET  /              - Root welcome message & API directory
  GET  /health        - Service health & model version check
  POST /predict       - Real-time event prediction & full explainable security pipeline
  POST /predict/batch - Batch inference through full pipeline
  POST /simulate      - Execute synthetic attack scenario through full pipeline
  GET  /docs          - Interactive Swagger UI documentation
"""

from typing import Any, Dict, List
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from ai.prediction.service import PredictionService
from ai.detection.hybrid_engine import HybridDetectionEngine
from ai.explainability.security_intel import SecurityIntelligenceLayer
from ai.correlation.risk_engine import DynamicRiskEngine
from ai.mitre.mapper import MitreMapper
from ai.correlation.event_correlator import EventCorrelator
from ai.correlation.timeline_builder import TimelineBuilder
from ai.detection.simulation import SimulationEngine
from ai.config import FASTAPI_PORT

app = FastAPI(
    title="Explainable AI Threat Prediction Microservice",
    version="1.0.0",
    description="Real-time threat detection inference API for Windows Event Logs",
)

prediction_service = PredictionService()
hybrid_engine = HybridDetectionEngine(prediction_service)
security_intel = SecurityIntelligenceLayer()
risk_engine = DynamicRiskEngine()
mitre_mapper = MitreMapper()
event_correlator = EventCorrelator()
timeline_builder = TimelineBuilder()
simulation_engine = SimulationEngine()


class EventPredictionRequest(BaseModel):
    """Pydantic model representing incoming log event features for prediction."""
    model_config = ConfigDict(extra="allow")

    scenario_id: str = "default_scen"
    EventID: int = 4624
    failed_login_count_5m: float = 0.0
    time_delta_prev_event: float = 0.0
    is_powershell_executed: int = 0
    privilege_escalation_flag: int = 0
    unusual_process_parent_ratio: float = 0.0
    session_duration: float = 0.0


class SimulationRequest(BaseModel):
    """Pydantic model representing simulation scenario trigger."""
    scenario_type: str = "FAILED_LOGIN_BURST"


def process_event_full_pipeline(features: Dict[str, Any]) -> Dict[str, Any]:
    """Execute complete end-to-end AI security pipeline on a single log event."""
    # 1. Hybrid Detection (ML + Signature Rules)
    alert_obj = hybrid_engine.process_event(features)

    # 2. SHAP & Security Intelligence Synthesis
    shap_vals = alert_obj.get("shap_values", {})
    intel_pkg = security_intel.generate_intelligence_package(alert_obj, shap_vals)

    # 3. Correlation Engine & Timeline Graph Construction
    corr_res = event_correlator.correlate_event(alert_obj)
    context_key = corr_res["context_key"]
    incident_data = event_correlator.active_incidents.get(context_key, {})
    incident_evts = corr_res.get("incident_events", incident_data.get("events", []))
    timeline_nodes = timeline_builder.build_timeline_nodes(incident_evts)



    # 4. Cumulative Multi-Factor Dynamic Risk Assessment
    total_rules = corr_res.get("total_rules", [])
    total_rules_count = len(total_rules)
    unique_hosts_count = corr_res.get("unique_hosts_count", 1)

    max_severity_score = 5.0
    for evt in incident_data.get("events", []):
        eid = evt.get("event_id", evt.get("raw_event", {}).get("EventID", 0))
        if eid in [4672, 4720, 4732, 7045]:
            max_severity_score = 15.0
        elif eid in [4625, 4688] and max_severity_score < 10.0:
            max_severity_score = 10.0

    risk_res = risk_engine.calculate_risk_score(
        alert_obj,
        chain_length=corr_res["chain_length"],
        impacted_hosts_count=unique_hosts_count,
        total_rules_count=total_rules_count,
        max_event_severity_score=max_severity_score
    )

    # 5. MITRE ATT&CK Mapping
    mitre_res = mitre_mapper.map_event_to_mitre(alert_obj)

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
        "mitre_mapping": mitre_res,
        "timeline_nodes": timeline_nodes,
        "raw_event": features
    }


@app.get("/")
def root_welcome() -> Dict[str, Any]:
    """Root endpoint welcoming users and providing service endpoints."""
    return {
        "message": "Welcome to the Explainable AI Threat Prediction Microservice",
        "status": "online",
        "documentation": "/docs",
        "health_check": "/health",
        "predict_endpoint": "/predict (POST)",
        "simulate_endpoint": "/simulate (POST)",
        "reset_endpoint": "/simulate/reset (POST)"
    }


@app.get("/health")
def health_check() -> Dict[str, Any]:
    """Check prediction microservice health and loaded model status."""
    return {
        "status": "healthy",
        "service": "AI Prediction Engine",
        "artifacts_loaded": prediction_service.is_loaded,
        "model_version": prediction_service.metadata.get("model_name", "v1.0.0"),
    }


@app.post("/predict")
def predict_event(request: EventPredictionRequest) -> Dict[str, Any]:
    """Execute complete AI security pipeline on a single event."""
    features = request.model_dump()
    result = process_event_full_pipeline(features)
    return result


@app.post("/predict/batch")
def predict_batch(events: List[EventPredictionRequest]) -> Dict[str, Any]:
    """Execute complete AI security pipeline on a batch of event objects."""
    results = [process_event_full_pipeline(req.model_dump()) for req in events]
    return {"count": len(results), "predictions": results}


@app.post("/simulate")
def simulate_scenario(request: SimulationRequest) -> Dict[str, Any]:
    """Generate synthetic attack scenario events and run them through the full pipeline."""
    events = simulation_engine.generate_scenario_events(request.scenario_type)
    results = [process_event_full_pipeline(evt) for evt in events]
    return {
        "scenario_type": request.scenario_type,
        "event_count": len(results),
        "pipeline_results": results
    }


@app.post("/simulate/reset")
def reset_simulation_state() -> Dict[str, Any]:
    """Reset active enterprise incident correlation state and MITRE state."""
    event_correlator.reset()
    mitre_mapper.reset()
    return {"message": "AI Engine simulation state reset successfully."}



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=FASTAPI_PORT)

