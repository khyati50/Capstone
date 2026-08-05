# Phase 9 --- SHAP Explainability System

> Project: Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Integrate SHAP (SHapley Additive exPlanations) to explain every AI
prediction in a transparent and analyst-friendly manner.

Unlike traditional ML systems that only output a prediction, this phase
enables the system to explain *why* an alert was generated.

------------------------------------------------------------------------

# Why This Phase Exists

One of the major limitations of AI-based intrusion detection systems is
that they behave like black boxes.

Security analysts require evidence before trusting an alert.

SHAP bridges the gap between AI predictions and human understanding.

------------------------------------------------------------------------

# Inputs

-   Production Model (Phase 6)
-   Hybrid Detection Output (Phase 8)

------------------------------------------------------------------------

# Explainability Goals

For every prediction the system should answer:

-   Why was this event classified as malicious?
-   Which features contributed most?
-   Which features reduced the risk?
-   How confident is the model?

------------------------------------------------------------------------

# SHAP Strategy

Use SHAP as the primary Explainable AI technique.

Two explanation levels:

## Local Explanation

Explain one prediction.

Example:

-   Event ID 4625
-   Failed Login Count
-   PowerShell Execution

These features contributed most to the alert.

## Global Explanation

Explain overall model behaviour.

Examples:

-   Most important features
-   Frequently used indicators
-   Feature ranking

------------------------------------------------------------------------

# Explainability Pipeline

Windows Event

↓

Prediction

↓

SHAP

↓

Feature Importance

↓

Human-readable Explanation

↓

Security Intelligence Layer

------------------------------------------------------------------------

# Expected SHAP Output

For every alert:

-   Prediction
-   Confidence
-   Top Positive Features
-   Top Negative Features
-   SHAP Values

------------------------------------------------------------------------

# Dashboard Integration

The dashboard should display:

-   Feature importance chart
-   Top contributing events
-   Confidence score
-   Explanation summary

------------------------------------------------------------------------

# Deliverables

-   SHAP integration
-   Local explanations
-   Global explanations
-   Explainability documentation

------------------------------------------------------------------------

# Common Mistakes

-   Showing raw SHAP values to analysts.
-   Treating SHAP as the final explanation.
-   Ignoring negative feature contributions.
-   Using explanations without validating feature quality.

------------------------------------------------------------------------

# Outputs

The SHAP system provides structured explanations to the:

-   Security Intelligence Layer
-   Dashboard
-   Risk Assessment

------------------------------------------------------------------------

# Notes

SHAP is **not** the final novelty of the project.

It explains the AI model.

The next phase transforms SHAP output into analyst-friendly security
intelligence, which is the primary research contribution of this
project.
