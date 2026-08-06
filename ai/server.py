"""FastAPI Prediction Service Application Server.

Runs AI prediction microservice on port 8000.
Endpoints:
  POST /predict       - Real-time event prediction & SHAP explanation
  POST /predict/batch - Batch inference
  GET  /health        - Service health & model version check
"""

from typing import Any, Dict, List
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ai.prediction.service import PredictionService
from ai.config import FASTAPI_PORT

app = FastAPI(
    title="Explainable AI Threat Prediction Microservice",
    version="1.0.0",
    description="Real-time threat detection inference API for Windows Event Logs",
)

prediction_service = PredictionService()


class EventPredictionRequest(BaseModel):
    """Pydantic model representing incoming log event features for prediction."""
    scenario_id: str = "default_scen"
    EventID: int = 4624
    failed_login_count_5m: float = 0.0
    time_delta_prev_event: float = 0.0
    is_powershell_executed: int = 0
    privilege_escalation_flag: int = 0
    unusual_process_parent_ratio: float = 0.0
    session_duration: float = 0.0


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
    """Execute model inference and SHAP explainability on a single event."""
    features = request.model_dump()
    result = prediction_service.predict_single(features)
    return result


@app.post("/predict/batch")
def predict_batch(events: List[EventPredictionRequest]) -> Dict[str, Any]:
    """Execute model inference on a batch of event objects."""
    results = []
    for req in events:
        res = prediction_service.predict_single(req.model_dump())
        results.append(res)
    return {"count": len(results), "predictions": results}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=FASTAPI_PORT)
