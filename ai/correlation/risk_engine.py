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

from typing import Dict, Any


class DynamicRiskEngine:
    """Dynamic Risk Scoring Engine."""

    def __init__(self) -> None:
        """Initialize DynamicRiskEngine instance."""
        pass

    def calculate_risk_score(
        self,
        alert_object: Dict[str, Any],
        chain_length: int = 1,
        impacted_hosts_count: int = 1
    ) -> Dict[str, Any]:
        """Compute dynamic risk score (0-100) and risk level.

        Args:
            alert_object: Alert output dictionary.
            chain_length: Number of correlated events in attack chain.
            impacted_hosts_count: Number of unique hosts impacted.

        Returns:
            Dictionary with numeric score, qualitative level, and breakdown.
        """
        confidence = float(alert_object.get("confidence", 0.5))
        triggered_rules = alert_object.get("triggered_rules", [])
        rules_count = len(triggered_rules)
        event_id = int(alert_object.get("event_id", 0))

        # Factor 1: AI Confidence (0-30 points)
        f_ai = confidence * 30.0

        # Factor 2: Rule Count (0-20 points)
        f_rules = min(20.0, rules_count * 10.0)

        # Factor 3: Event ID Severity (0-15 points)
        f_event = 5.0
        if event_id in [4672, 4720, 4732, 7045]:
            f_event = 15.0
        elif event_id in [4625, 4688]:
            f_event = 10.0

        # Factor 4: Chain Progression (0-20 points)
        f_chain = min(20.0, (chain_length - 1) * 6.6)

        # Factor 5: Impacted Scope (0-15 points)
        f_scope = min(15.0, impacted_hosts_count * 5.0)

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
