"""Security Intelligence Layer — PRIMARY RESEARCH NOVELTY.

Translates technical SHAP weights and rule triggers into structured,
analyst-friendly human-readable security intelligence:
1. HumanReadableExplanationGenerator: Converts raw weights to human security logic
2. ThreatSummaryModule: Constructs structured alert narrative
3. EvidenceAggregator: Bundles AI + Rule + Log parameters into evidence package
4. InvestigationRecommendationModule: Actionable SOC playbooks and guidance
"""

from typing import Dict, Any

EXPLANATION_TEMPLATES: Dict[str, str] = {
    "failed_login_count_5m": "High frequency of failed login attempts ({failed_cnt}) detected within 5 minutes.",
    "is_powershell_executed": "Suspicious PowerShell, pwsh, or obfuscated script executed with script arguments.",
    "privilege_escalation_flag": "Sensitive administrator privileges assigned to current user session.",
    "unusual_process_parent_ratio": "Rare parent-child process execution path detected (ratio: {ratio:.2f}).",
    "session_duration": "Anomalous user session duration observed ({val:.0f} seconds).",
    "time_delta_prev_event": "Rapid event execution velocity detected ({val:.1f}s elapsed since prior event).",
}


class SecurityIntelligenceLayer:
    """Primary Research Novelty Layer converting SHAP values to SOC Intelligence."""

    def __init__(self, templates: Dict[str, str] = None) -> None:
        """Initialize SecurityIntelligenceLayer instance with configurable templates."""
        self.templates = templates or EXPLANATION_TEMPLATES

    def generate_intelligence_package(
        self, alert_object: Dict[str, Any], shap_values: Dict[str, float]
    ) -> Dict[str, Any]:
        """Generate full human-readable security intelligence report.

        Args:
            alert_object: Unified alert dict from Hybrid Detection Engine.
            shap_values: Dictionary of SHAP feature weights.

        Returns:
            Dictionary containing natural language explanation, summary, evidence, and recommendations.
        """
        raw_event = alert_object.get("raw_event", {})
        severity = alert_object.get("severity", "Medium")
        confidence = alert_object.get("confidence", 0.8)
        user = raw_event.get("TargetUserName", raw_event.get("SubjectUserName", "UnknownUser"))
        host = raw_event.get("Computer", "UnknownHost")

        # 1. Template-driven Human-Readable Explanation Generator (Item 5)
        human_reasons = []
        for feature, weight in shap_values.items():
            if weight > 0.10:
                if feature in self.templates:
                    tpl = self.templates[feature]
                    if feature == "failed_login_count_5m":
                        failed_cnt = raw_event.get("failed_login_count_5m", 0)
                        human_reasons.append(tpl.format(failed_cnt=failed_cnt))
                    elif feature == "unusual_process_parent_ratio":
                        ratio = float(raw_event.get("unusual_process_parent_ratio", 0.0))
                        human_reasons.append(tpl.format(ratio=ratio))
                    elif feature in ["session_duration", "time_delta_prev_event"]:
                        val = float(raw_event.get(feature, 0.0))
                        human_reasons.append(tpl.format(val=val))
                    else:
                        human_reasons.append(tpl)
                else:
                    human_reasons.append(f"Anomalous metric observed for '{feature}' (weight: +{weight:.2f}).")

        if not human_reasons:
            human_reasons.append("Behavioral event attributes deviated from baseline historical activity.")

        # 2. Threat Summary Module
        threat_type = "Potential Security Incident"
        if raw_event.get("is_powershell_executed") == 1:
            threat_type = "Suspicious Execution / PowerShell Abuse"
        elif raw_event.get("privilege_escalation_flag") == 1:
            threat_type = "Privilege Escalation Activity"
        elif float(raw_event.get("failed_login_count_5m", 0)) >= 3:
            threat_type = "Credential Access / Brute Force Attack"

        threat_summary = (
            f"[{severity} Severity - {confidence*100:.0f}% Confidence] {threat_type} detected on host '{host}' "
            f"targeting user '{user}'."
        )

        # 3. Evidence Aggregator
        evidence_package = {
            "ai_confidence_percent": round(confidence * 100, 1),
            "triggered_rules_count": len(alert_object.get("triggered_rules", [])),
            "primary_indicators": human_reasons,
            "raw_log_context": {
                "EventID": raw_event.get("EventID"),
                "Computer": host,
                "User": user,
                "ProcessName": raw_event.get("ProcessName", "N/A"),
                "CommandLine": raw_event.get("CommandLine", "N/A"),
            },
        }

        # 4. Actionable Investigation Recommendation Module (SOC Playbook)
        recommendations = [
            f"1. Immediately inspect active user session for account '{user}' on host '{host}'.",
            "2. Verify whether process execution was authorized by system administrator.",
            "3. If credential brute-forcing is suspected, lock user account and enforce password reset.",
            "4. Isolate impacted endpoint if lateral movement indicators are confirmed.",
        ]

        return {
            "threat_summary": threat_summary,
            "threat_type": threat_type,
            "human_readable_explanation": " ".join(human_reasons),
            "evidence_package": evidence_package,
            "investigation_recommendations": recommendations,
        }
