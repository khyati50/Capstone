import sys, os, json

sys.path.insert(0, os.getcwd())
from ai.correlation.risk_engine import DynamicRiskEngine

eng = DynamicRiskEngine()

common = {
    "confidence": 0.92,
    "triggered_rules": ["R1"],
    "alert_source": "AI_AND_RULE_AGREEMENT",
}

sims = {
    "FAILED_LOGIN_BURST": {
        "alert_object": {**common, "event_id": 4625},
        "event_sequence": [4625, 4625, 4625, 4625, 4625, 4625],
        "impacted_hosts_count": 1,
        "unique_users_count": 1,
        "total_rules_count": 1,
    },
    "SUSPICIOUS_POWERSHELL": {
        "alert_object": {**common, "event_id": 4688},
        "event_sequence": [4688],
        "impacted_hosts_count": 1,
        "unique_users_count": 1,
        "total_rules_count": 1,
    },
    "PRIVILEGE_ESCALATION": {
        "alert_object": {**common, "event_id": 4672},
        "event_sequence": [4672],
        "impacted_hosts_count": 1,
        "unique_users_count": 1,
        "total_rules_count": 1,
    },
    "NEW_ADMIN_ACCOUNT": {
        "alert_object": {**common, "event_id": 4720},
        "event_sequence": [4720, 4732],
        "impacted_hosts_count": 1,
        "unique_users_count": 1,
        "total_rules_count": 2,
    },
}

out = {}
for name, params in sims.items():
    res = eng.calculate_risk_score(
        alert_object=params["alert_object"],
        event_sequence=params["event_sequence"],
        impacted_hosts_count=params["impacted_hosts_count"],
        unique_users_count=params["unique_users_count"],
        total_rules_count=params["total_rules_count"],
        mitre_techniques=[],
        alert_source=params["alert_object"].get("alert_source"),
    )
    out[name] = res

print(json.dumps(out, indent=2))
