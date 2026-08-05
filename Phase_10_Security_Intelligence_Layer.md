# Phase 10 --- Security Intelligence Layer (Primary Novelty)

> Project: Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

## Objective

Transform AI predictions and SHAP outputs into analyst-friendly security
intelligence.

## Why This Phase Exists

Traditional AI systems stop at prediction and confidence. This project
converts technical outputs into explanations, evidence summaries, and
investigation guidance that security analysts can immediately use.

## Inputs

-   Hybrid Detection Output
-   SHAP Explanations
-   Rule Engine Results
-   Windows Event Metadata

## Workflow

Windows Event → AI Prediction → SHAP → Security Intelligence Layer →
Human-readable Explanation → Threat Summary → Dashboard

## Responsibilities

### Human-readable Explanations

Convert feature importance into understandable security reasoning.

### Threat Summary

Generate: - Threat Type - Severity - Confidence - Evidence - Host -
User - Timestamp

### Evidence Aggregation

Combine: - AI prediction - Rule matches - SHAP - Event metadata

### Investigation Guidance

Recommend actions such as: - Review login history - Inspect PowerShell
activity - Verify privilege changes - Investigate suspicious processes

## Dashboard

Display: - Threat Summary - Explanation - Evidence - Suggested
Investigation

## Deliverables

-   Explanation Generator
-   Threat Summary Module
-   Evidence Aggregator
-   Investigation Recommendation Module

## Common Mistakes

-   Displaying raw SHAP values
-   Generic explanations
-   Ignoring supporting evidence
-   Mixing explanations with automatic remediation

## Outputs

Provides enriched alerts to: - Event Correlation - Risk Assessment -
MITRE ATT&CK Mapping - SOC Dashboard

## Research Contribution

This is the primary novelty of the project. Instead of presenting only
AI predictions, the system produces interpretable, evidence-backed,
analyst-oriented security intelligence suitable for real-world SOC
investigations.
