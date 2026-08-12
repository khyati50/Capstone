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
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from ai.config import FASTAPI_PORT
from ai.detection.simulation import SimulationEngine
from ai.pipeline.orchestrator import LivePipelineOrchestrator

app = FastAPI(
    title="Explainable AI Threat Prediction Microservice",
    version="1.0.0",
    description="Real-time threat detection inference API for Windows Event Logs",
)

pipeline_orchestrator = LivePipelineOrchestrator()
prediction_service = pipeline_orchestrator.prediction_service
hybrid_engine = pipeline_orchestrator.hybrid_engine
security_intel = pipeline_orchestrator.security_intel
risk_engine = pipeline_orchestrator.risk_engine
mitre_mapper = pipeline_orchestrator.mitre_mapper
event_correlator = pipeline_orchestrator.event_correlator
timeline_builder = pipeline_orchestrator.timeline_builder
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
    """Execute complete end-to-end AI security pipeline on a single log event via LivePipelineOrchestrator."""
    return pipeline_orchestrator.process_event(features)


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
        "reset_endpoint": "/simulate/reset (POST)",
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
    return {"scenario_type": request.scenario_type, "event_count": len(results), "pipeline_results": results}


@app.post("/simulate/reset")
def reset_simulation_state() -> Dict[str, Any]:
    """Reset active enterprise incident correlation state and MITRE state."""
    event_correlator.reset()
    mitre_mapper.reset()
    return {"message": "AI Engine simulation state reset successfully."}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=FASTAPI_PORT)
