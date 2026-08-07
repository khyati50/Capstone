# MITRE Bug Fix Sprint
## Root Cause Analysis & Functional Validation

## Objective
The MITRE ATT&CK Framework Mapping is currently leaking cross-scenario techniques due to global state accumulation in the Python engine.

Objectives:
1. Trace the complete request flow.
2. Identify the exact root cause.
3. Fix only the MITRE-related issue.
4. Validate every simulation.

Do not redesign the architecture.

## Current Behaviour
- Failed Login Burst: Maps T1110.
- Suspicious Obfuscated PowerShell: Incorrectly includes T1110 from previous scenario alongside T1059.001.
- Special Privilege Assignment: Incorrectly includes T1110 and T1059.001 alongside T1078.
- New Local Admin Account Created: Incorrectly includes all previous scenario techniques alongside T1136.001 and T1069.001.

## Required Investigation
Trace:
Simulation.jsx / App.jsx
→ POST /api/simulate/scenario
→ FastAPI /simulate
→ SimulationEngine.generate_scenario_events()
→ process_event_full_pipeline()
→ MitreMapper.map_event_to_mitre()
→ saveProcessedPipelineResult()
→ Socket.IO mitre_update
→ MitreMatrix.jsx

Verify Technique IDs:
- T1110 (Brute Force)
- T1059.001 (Command and Scripting Interpreter: PowerShell)
- T1078 (Valid Accounts)
- T1136.001 (Create Account: Local Account)
- T1069.001 (Permission Group Discovery / Local Groups)

## Requirements
- Generate MITRE mappings accurately per event/scenario.
- Do not leak cross-scenario techniques.
- Preserve the architecture.
- Modify only files required for this fix.
- Do not modify Timeline.
- Do not modify Risk Assessment.
- Do not modify Alert Center.
- Do not implement unrelated improvements.

## Validation
After Reset Simulation:
1. Failed Login Burst → T1110
2. PowerShell → T1059.001
3. Privilege Assignment → T1078
4. Local Admin Created → T1136.001, T1069.001

## Success Criteria
- Every simulation generates only its own MITRE techniques.
- No missing MITRE mappings.
- No cross-scenario technique leakage.

## Deliverables
Report:
- Root cause
- Files modified
- Why cross-scenario leakage occurred
- Fix explanation
- Validation results
- Remaining limitations

Stop after completing this sprint.
