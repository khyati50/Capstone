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

    def __init__(self, prediction_service: PredictionService = None) -> None:
        """Initialize HybridDetectionEngine with prediction service and rule engine.

        Args:
            prediction_service: Optional PredictionService instance.
        """
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

        ai_pred = ai_res.get("prediction", 0)
        ai_conf = float(ai_res.get("confidence", 0.5))

        has_rules = len(triggered_rules) > 0
        has_ai = ai_pred == 1

        # 1. Rule confidence calculation (Item 7)
        rule_conf = 0.0
        if has_rules:
            max_rule_sev = "Medium"
            for r in triggered_rules:
                if r.get("severity") == "Critical":
                    max_rule_sev = "Critical"
                elif r.get("severity") == "High" and max_rule_sev != "Critical":
                    max_rule_sev = "High"

            rule_conf = 0.95 if max_rule_sev == "Critical" else (0.85 if max_rule_sev == "High" else 0.70)

        # 2. Event severity factor
        event_id = int(event.get("EventID", 0))
        event_sev_factor = 0.90 if event_id in [4672, 4720, 4732, 7045] else (0.75 if event_id in [4625, 4688] else 0.40)

        # 3. Weighted Confidence Fusion
        if has_ai and has_rules:
            alert_source = "AI_AND_RULE_AGREEMENT"
            fused_conf = (0.45 * ai_conf) + (0.35 * rule_conf) + (0.20 * event_sev_factor)
            severity = "Critical" if fused_conf > 0.82 else "High"
            final_conf = max(fused_conf, 0.92)
        elif has_ai and not has_rules:
            alert_source = "AI_ANOMALY_ONLY"
            fused_conf = (0.70 * ai_conf) + (0.30 * event_sev_factor)
            severity = "High" if fused_conf > 0.75 else "Medium"
            final_conf = fused_conf
        elif not has_ai and has_rules:
            alert_source = "RULE_SIGNATURE_ONLY"
            fused_conf = (0.65 * rule_conf) + (0.35 * event_sev_factor)
            severity = triggered_rules[0].get("severity", "Medium")
            final_conf = fused_conf
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
