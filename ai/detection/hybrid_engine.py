"""Hybrid Detection Engine (Decision Fusion of AI Model + Rule Engine).

Merges AI model predictions with deterministic rule evaluation into a single
unified alert object. Handles:
- AI-Only Alert (High novelty anomaly)
- Rule-Only Alert (Signature match)
- AI + Rule Agreement (Highest priority & confidence)
"""

from typing import Dict, Any
from ai.detection.rule_engine import RuleEngine
from ai.prediction.service import PredictionService


class HybridDetectionEngine:
    """Decision Fusion hybrid detection controller."""

    def __init__(self, prediction_service: PredictionService = None):
        self.prediction_service = prediction_service or PredictionService()
        self.rule_engine = RuleEngine()

    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process log event through AI model and Rule Engine, returning unified alert object.

        Args:
            event: Event metadata dictionary.

        Returns:
            Unified alert object dictionary.
        """
        ai_res = self.prediction_service.predict_single(event)
        triggered_rules = self.rule_engine.evaluate_rules(event)

        ai_pred = ai_res.get("prediction", 0)
        ai_conf = ai_res.get("confidence", 0.5)

        has_rules = len(triggered_rules) > 0
        has_ai = ai_pred == 1

        if has_ai and has_rules:
            alert_source = "AI_AND_RULE_AGREEMENT"
            severity = "Critical" if ai_conf > 0.8 else "High"
            final_conf = max(ai_conf, 0.95)
        elif has_ai and not has_rules:
            alert_source = "AI_ANOMALY_ONLY"
            severity = "High" if ai_conf > 0.85 else "Medium"
            final_conf = ai_conf
        elif not has_ai and has_rules:
            alert_source = "RULE_SIGNATURE_ONLY"
            severity = triggered_rules[0].get("severity", "Medium")
            final_conf = 0.85
        else:
            alert_source = "BENIGN"
            severity = "Low"
            final_conf = 0.95

        is_alert = (alert_source != "BENIGN")

        return {
            "is_alert": is_alert,
            "scenario_id": event.get("scenario_id", "live_stream"),
            "event_id": event.get("EventID", 0),
            "alert_source": alert_source,
            "severity": severity,
            "confidence": round(final_conf, 4),
            "triggered_rules": triggered_rules,
            "shap_values": ai_res.get("shap_values", {}),
            "raw_event": event,
        }
