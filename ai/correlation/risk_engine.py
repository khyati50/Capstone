"""Dynamic Risk Assessment Engine (0 - 100 Score Escalation).

Calculates dynamic threat risk scores based on:
- AI Confidence Probability (30% weight)
- Concurrent Triggered Rules Count (20% weight)
- Event ID Severity Rating (15% weight)
- Attack Chain Progression Length (20% weight)
- Impacted Host/User Scope (15% weight)

Maps numeric score to qualitative level:
Low (0-25), Medium (26-50), High (51-75), Critical (76-100).
"""

from typing import Dict, Any, List
from ai.config import RISK_ENGINE_CONFIG, CRITICAL_EVENT_IDS, HIGH_EVENT_IDS


class DynamicRiskEngine:
    """Dynamic Risk Scoring Engine."""

    def __init__(self, config: Dict[str, float] = None) -> None:
        """Initialize DynamicRiskEngine instance with configurable weights."""
        self.config = config or RISK_ENGINE_CONFIG

    def calculate_risk_score(
        self,
        alert_object: Dict[str, Any],
        chain_length: int = 1,
        impacted_hosts_count: int = 1,
        total_rules_count: int = 0,
        max_event_severity_score: float = 10.0
    ) -> Dict[str, Any]:
        """Compute cumulative dynamic risk score (0-100) and risk level using configurable weights.

        Args:
            alert_object: Alert output dictionary.
            chain_length: Cumulative number of correlated events in attack chain.
            impacted_hosts_count: Number of unique hosts impacted.
            total_rules_count: Total unique rules triggered across cumulative incident.
            max_event_severity_score: Highest event severity score across incident.

        Returns:
            Dictionary with numeric score, qualitative level, and breakdown.
        """
        confidence = float(alert_object.get("confidence", 0.5))
        current_rules = len(alert_object.get("triggered_rules", []))
        effective_rules_count = max(total_rules_count, current_rules)

        event_id = int(alert_object.get("event_id", 0))

        ai_max = self.config.get("ai_confidence_max_points", 30.0)
        rules_max = self.config.get("rule_hits_max_points", 20.0)
        event_max = self.config.get("event_severity_max_points", 15.0)
        chain_max = self.config.get("chain_length_max_points", 20.0)
        scope_max = self.config.get("scope_max_points", 15.0)

        # Factor 1: AI Confidence (0-30 points)
        f_ai = min(ai_max, confidence * ai_max)

        # Factor 2: Rule Count (0-20 points, cumulative across simulations)
        f_rules = min(rules_max, effective_rules_count * 6.7)

        # Factor 3: Event ID Severity (0-15 points, max across incident using config lists)
        f_event = 5.0
        if event_id in CRITICAL_EVENT_IDS or max_event_severity_score >= 15.0:
            f_event = event_max
        elif event_id in HIGH_EVENT_IDS or max_event_severity_score >= 10.0:
            f_event = 10.0

        # Factor 4: Chain Progression (0-20 points, cumulative length)
        f_chain = min(chain_max, chain_length * 2.5)

        # Factor 5: Impacted Scope (0-15 points)
        f_scope = min(scope_max, impacted_hosts_count * 7.5)

        total_score = min(100.0, round(f_ai + f_rules + f_event + f_chain + f_scope, 1))


        if total_score >= 76.0:
            level = "Critical"
        elif total_score >= 51.0:
            level = "High"
        elif total_score >= 26.0:
            level = "Medium"
        else:
            level = "Low"

        return {
            "score": total_score,
            "level": level,
            "breakdown": {
                "ai_confidence_weight": round(f_ai, 1),
                "rule_hits_weight": round(f_rules, 1),
                "event_severity_weight": round(f_event, 1),
                "chain_length_weight": round(f_chain, 1),
                "scope_weight": round(f_scope, 1),
            },
        }

