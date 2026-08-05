# Phase 8 --- Hybrid Detection Engine

> Project: Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Design the core detection engine that combines Machine Learning and
Rule-Based Detection to identify both known attacks and previously
unseen suspicious behaviour.

------------------------------------------------------------------------

# Why Hybrid Detection?

No single detection technique is sufficient.

## AI Strengths

-   Detects behavioural anomalies
-   Identifies previously unseen attacks
-   Learns complex patterns

Limitations: - False positives - Difficult to interpret without SHAP

## Rule Engine Strengths

-   Detects known attack patterns
-   Fast and deterministic
-   Easy to explain

Limitations: - Cannot detect unknown attacks

A hybrid approach combines the strengths of both.

------------------------------------------------------------------------

# Architecture

Windows Event │ ▼ Preprocessing │ ├──────────────┐ ▼ ▼ AI Detection Rule
Engine │ │ └──────┬───────┘ ▼ Decision Fusion ▼ Unified Detection ▼
SHAP + Security Layer

------------------------------------------------------------------------

# AI Detection

Responsibilities

-   Behavioural analysis
-   Classification
-   Confidence score
-   Feature importance (later via SHAP)

Output

-   Prediction
-   Confidence

------------------------------------------------------------------------

# Rule Engine

Detects predefined attacks such as:

-   Brute Force
-   Privilege Escalation
-   Suspicious PowerShell
-   New Administrator Creation
-   Persistence Indicators

Rules are stored separately from application logic for easier
maintenance.

------------------------------------------------------------------------

# Decision Fusion

Combine AI and rule outputs into a single decision.

Possible outcomes:

-   AI only alert
-   Rule only alert
-   AI + Rule agreement (highest confidence)

This prevents duplicate alerts and simplifies downstream processing.

------------------------------------------------------------------------

# Detection Workflow

1.  Receive event
2.  Preprocess
3.  Execute rule engine
4.  Execute AI model
5.  Merge results
6.  Generate unified alert
7.  Forward to SHAP and downstream modules

------------------------------------------------------------------------

# Alert Structure

Each alert should contain:

-   Alert ID
-   Timestamp
-   Event ID
-   Prediction
-   Confidence
-   Triggered Rules
-   Severity
-   Status

------------------------------------------------------------------------

# Folder Structure

hybrid_detection/ - ai/ - rules/ - fusion/ - alerts/

------------------------------------------------------------------------

# Deliverables

-   Hybrid detection architecture
-   Rule repository
-   Decision fusion logic
-   Unified alert format
-   Detection documentation

------------------------------------------------------------------------

# Common Mistakes

-   Running separate pipelines for AI and rules
-   Duplicating alerts
-   Hardcoding rules in backend code
-   Ignoring confidence scores

------------------------------------------------------------------------

# Outputs

The hybrid detection engine provides input to:

-   SHAP Explainability
-   Security Intelligence Layer
-   Event Correlation
-   Risk Assessment
-   Dashboard

------------------------------------------------------------------------

# Notes

The Hybrid Detection Engine is the core of the project.

It should produce one consistent detection result regardless of whether
an alert originated from AI, rules, or both. This unified output
simplifies all later phases and makes the system easier to maintain and
extend.
