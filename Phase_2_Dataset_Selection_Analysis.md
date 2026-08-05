# Phase 2 --- Dataset Selection & Analysis

> Project: Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

## Goal

Select and justify the most suitable Windows Event Log dataset before
preprocessing or model training.

## Final Dataset

**Primary Dataset:** Atomic-EVTX

### Reasons

-   Windows Event Logs (Security, System, Application, Sysmon,
    PowerShell)
-   1000+ attack scenarios
-   Includes benign activity
-   Direct MITRE ATT&CK mapping
-   JSON available
-   Suitable for SHAP
-   Supports event correlation
-   Matches enterprise Windows security use case

## Other Datasets Considered

-   EVTX-ATTACK-SAMPLES
-   OTRF/Mordor
-   LANL
-   Other synthetic datasets

## Design Decisions

### Keep all attack scenarios

Retain all attack scenarios for maximum behavioral diversity.

### Curate Event IDs

Use a domain-informed subset of security-relevant Event IDs. Refine
after EDA. Remove noise while preserving attack chains.

### Dataset Version

Use: `attacks_by_category_atomic_and_tools_removed`

Reason: Behavioral detection instead of signature/tool-name detection.

### Dataset Split

Use scenario-level splitting.

-   Train: 70%
-   Validation: 15%
-   Test: 15%

Never split individual events from the same scenario.

## Deliverables

-   Dataset selected
-   Dataset comparison
-   Dataset justification
-   Event ID inventory
-   Feature inventory
-   Preprocessing plan

## Excluded From This Phase

-   Preprocessing
-   Feature engineering
-   Model training
-   SHAP
-   Backend
-   Dashboard

## Notes

The Event ID list is provisional and will be refined after Exploratory
Data Analysis (EDA).
