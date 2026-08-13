"""Dynamic Risk Assessment Engine (0 - 100 Score Escalation).

Calculates dynamic threat risk scores based on 5 approved factors (Final Spec):
1. AI Detection Confidence (max 25 pts) — Threshold-gated linear function (NIST SP 800-30)
2. Rule Engine Coverage (max 20 pts) — Logarithmic scaling (Dempster-Shafer / Bayesian reasoning)
3. MITRE ATT&CK Tactic Stage (max 20 pts) — Highest kill-chain stage present in incident
4. Attack Tactic Diversity (max 20 pts) — Count of distinct MITRE tactics observed (progression over volume)
5. Impacted Host & User Scope (max 15 pts) — Stepped evaluation based on combined host + user count

Post-Scoring Adjustment:
- Corroboration Multiplier (×1.00 – ×1.15) applied multiplicatively

Qualitative Risk Levels:
Low (0-25), Medium (26-50), High (51-75), Critical (76-100).
"""

import math
from typing import Any, Dict, List

from ai.config import (
    CORROBORATION_MULTIPLIER,
    EVENT_TO_TACTIC,
    RISK_ENGINE_CONFIG,
    TACTIC_DIVERSITY_SCORES,
    TACTIC_STAGE_SCORES,
)


class DynamicRiskEngine:
    """Dynamic Risk Scoring Engine implementing the approved Final Spec formula."""

    def __init__(self, config: Dict[str, float] = None) -> None:
        """Initialize DynamicRiskEngine instance with configurable weights."""
        self.config = config or RISK_ENGINE_CONFIG

    def calculate_risk_score(
        self,
        alert_object: Dict[str, Any],
        chain_length: int = 1,
        impacted_hosts_count: int = 1,
        unique_users_count: int = 1,
        total_rules_count: int = 0,
        mitre_techniques: List[Dict[str, Any]] = None,
        alert_source: str = "AI_ANOMALY_ONLY",
        event_sequence: List[int] = None,
        max_event_severity_score: float = 10.0,
    ) -> Dict[str, Any]:
        """Compute cumulative dynamic risk score (0-100) and risk level using approved factors.

        Args:
            alert_object: Alert output dictionary.
            chain_length: Cumulative number of correlated events in attack chain.
            impacted_hosts_count: Number of unique hosts impacted.
            unique_users_count: Number of unique users impacted.
            total_rules_count: Total unique rules triggered across cumulative incident.
            mitre_techniques: List of MITRE technique dicts for the incident.
            alert_source: Alert source type string.
            event_sequence: List of Event IDs in incident chain sequence.
            max_event_severity_score: Backward compatible parameter.

        Returns:
            Dictionary with numeric score, qualitative level, breakdown, and explainable sublines.
        """
        raw_event = alert_object.get("raw_event", {})
        event_id = int(alert_object.get("event_id", alert_object.get("EventID", raw_event.get("EventID", 0))))

        # Factor 1: AI Confidence (max 25 pts)
        confidence = float(alert_object.get("confidence", 0.5))
        ai_max = float(self.config.get("ai_confidence_max_points", 25.0))
        f_ai = min(ai_max, max(0.0, (confidence - 0.50) / 0.50) * ai_max)

        # Factor 2: Rule Coverage (max 20 pts)
        current_rules = alert_object.get("triggered_rules", [])
        effective_rules_count = max(total_rules_count, len(current_rules))
        rules_max = float(self.config.get("rule_hits_max_points", 20.0))
        max_rules_expected = 5
        if effective_rules_count <= 0:
            f_rules = 0.0
        else:
            f_rules = rules_max * (math.log2(1 + effective_rules_count) / math.log2(1 + max_rules_expected))

        # Factor 3: MITRE ATT&CK Tactic Stage (max 20 pts) — replaces Event Severity
        mitre_techs = mitre_techniques or []
        tactic_names = set(t.get("tactic", "") for t in mitre_techs if isinstance(t, dict) and t.get("tactic"))

        event_seq = event_sequence or [event_id]
        for eid in event_seq:
            if int(eid) in EVENT_TO_TACTIC:
                tactic_names.add(EVENT_TO_TACTIC[int(eid)])

        scores = [TACTIC_STAGE_SCORES.get(t, 3.0) for t in tactic_names if t in TACTIC_STAGE_SCORES]
        tactic_max = float(self.config.get("mitre_tactic_max_points", 20.0))
        f_tactic = min(tactic_max, float(max(scores)) if scores else 3.0)

        # Factor 4: Attack Tactic Diversity (max 20 pts) — replaces event-count chain length
        observed_tactics = set(EVENT_TO_TACTIC.get(int(eid)) for eid in event_seq if int(eid) in EVENT_TO_TACTIC)
        observed_tactics.update(tactic_names)
        observed_tactics.discard("")
        unique_tactic_count = len(observed_tactics)
        diversity_max = float(self.config.get("tactic_diversity_max_points", 20.0))
        f_chain = min(diversity_max, TACTIC_DIVERSITY_SCORES.get(unique_tactic_count, 20.0))

        # Factor 5: Host & User Scope (max 15 pts)
        combined_scope = impacted_hosts_count + unique_users_count
        scope_max = float(self.config.get("scope_max_points", 15.0))
        if combined_scope <= 1:
            f_scope = 5.0
        elif combined_scope == 2:
            f_scope = 7.5
        elif combined_scope <= 4:
            f_scope = 11.0
        elif combined_scope <= 8:
            f_scope = 13.5
        else:
            f_scope = 15.0
        f_scope = min(scope_max, f_scope)

        # Base score (pre-multiplier)
        base_score = min(100.0, f_ai + f_rules + f_tactic + f_chain + f_scope)

        # Corroboration Multiplier (×1.00 – ×1.15)
        src = alert_source or alert_object.get("alert_source", "AI_ANOMALY_ONLY")
        multiplier = CORROBORATION_MULTIPLIER.get(src, 1.0)

        final_score = round(min(100.0, base_score * multiplier), 1)

        if final_score >= 76.0:
            level = "Critical"
        elif final_score >= 51.0:
            level = "High"
        elif final_score >= 26.0:
            level = "Medium"
        else:
            level = "Low"

        # Construct explainable sublines generated dynamically from live data
        sorted_tactics = sorted(
            [t for t in tactic_names if t], key=lambda t: TACTIC_STAGE_SCORES.get(t, 0.0), reverse=True
        )
        primary_tactic = sorted_tactics[0] if sorted_tactics else "Unknown Tactic"
        tech_id = ""
        for t in mitre_techs:
            if isinstance(t, dict) and t.get("tactic") == primary_tactic:
                tech_id = t.get("technique_id", "")
                break
        if not tech_id:
            # Fallback map for technique ID if not directly in mitre_techs
            TECH_MAP = {4625: "T1110", 4688: "T1059.001", 4672: "T1078", 4720: "T1136.001", 4732: "T1069.001"}
            for eid in event_seq:
                if EVENT_TO_TACTIC.get(int(eid)) == primary_tactic:
                    tech_id = TECH_MAP.get(int(eid), "")
                    break

        tactic_sub = f"{primary_tactic}{' — ' + tech_id if tech_id else ''}"

        return {
            "score": final_score,
            "level": level,
            "breakdown": {
                "ai_confidence_weight": round(f_ai, 1),
                "rule_hits_weight": round(f_rules, 1),
                "mitre_tactic_weight": round(f_tactic, 1),
                "tactic_diversity_weight": round(f_chain, 1),
                "scope_weight": round(f_scope, 1),
                "corroboration_multiplier": multiplier,
                # Backward compatibility aliases
                "event_severity_weight": round(f_tactic, 1),
                "chain_length_weight": round(f_chain, 1),
            },
            "sublines": {
                "ai_confidence_subline": f"Model + rule agreement: {round(confidence * 100)}%",
                "rule_hits_subline": f"{effective_rules_count} unique detection rule{'s' if effective_rules_count != 1 else ''} matched",
                "mitre_tactic_subline": tactic_sub,
                "tactic_diversity_subline": f"{unique_tactic_count} distinct tactic{'s' if unique_tactic_count != 1 else ''} observed",
                "scope_subline": f"{impacted_hosts_count} host + {unique_users_count} user",
                "corroboration_subline": f"×{multiplier:.2f}",
            },
        }
