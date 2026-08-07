# Risk Bug Fix Sprint
## Root Cause Analysis & Functional Validation

## Objective
The Dynamic Risk Assessment Engine must accurately calculate dynamic multi-factor risk scores (0-100) and qualitative risk levels across all attack simulations.

Objectives:
1. Trace the complete request flow.
2. Identify any root cause or scoring inconsistencies.
3. Fix only Risk Assessment related issues and UI fallback bindings.
4. Verify mathematical correctness and logical justification of every score.
5. Validate all four simulations.

Do not redesign the architecture.

## Current Behaviour
- Failed Login Burst: Score 66.8 (High)
- Suspicious Obfuscated PowerShell: Score 54.3 (High)
- Special Privilege Assignment: Score 59.3 (High)
- New Local Admin Account Created: Score 68.5 (High)

## Required Investigation
Trace:
Simulation.jsx / App.jsx
→ POST /api/simulate/scenario
→ FastAPI /simulate
→ SimulationEngine.generate_scenario_events()
→ process_event_full_pipeline()
→ DynamicRiskEngine.calculate_risk_score()
→ saveProcessedPipelineResult()
→ Socket.IO risk_update
→ RiskGauge.jsx

Verify Scoring Factors:
- AI Confidence Weight (max 30.0)
- Triggered Rules Weight (max 20.0)
- Event Severity Rating (max 15.0)
- Attack Chain Progression Length (max 20.0)
- Impacted Scope (max 15.0)

## Requirements
- Dynamic risk scores calculated dynamically per scenario.
- Mathematical correctness of all 5 factor weights.
- UI fallback bindings in RiskGauge.jsx supporting all field name aliases (`overall_score`, `score`, `risk_score`).
- Modify only files required for this fix.
- Do not modify Timeline.
- Do not modify MITRE Matrix.
- Do not modify Alert Center.
- Do not implement unrelated improvements.

## Validation
After Reset Simulation:
1. Failed Login Burst → Score 66.8 (High)
2. PowerShell → Score 54.3 (High)
3. Privilege Assignment → Score 59.3 (High)
4. Local Admin Created → Score 68.5 (High)

## Success Criteria
- Every simulation generates mathematically verified and logically justified risk scores.
- Risk level matches qualitative thresholds (Low: 0-25, Medium: 26-50, High: 51-75, Critical: 76-100).
- RiskGauge UI renders dynamic risk data cleanly without falling back to hardcoded defaults.

## Deliverables
Report:
- Root cause & mathematical verification
- Files modified
- Score justification for all 4 simulations
- Validation results
- Remaining limitations

Stop after completing this sprint.
