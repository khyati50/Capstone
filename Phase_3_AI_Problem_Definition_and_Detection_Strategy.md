# Phase 3 --- AI Problem Definition & Detection Strategy

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Before preprocessing or training any model, clearly define:

-   What problem the AI is solving.
-   What the model should predict.
-   Which learning approach to use.
-   How predictions will be evaluated.
-   How the AI integrates with the rest of the system.

This phase establishes the AI architecture for the entire project.

------------------------------------------------------------------------

# Why This Phase Exists

A machine learning project should never begin with model training.

The prediction target, learning strategy, and evaluation methodology
must be finalized first.

All preprocessing, feature engineering, model training, and
explainability depend on these decisions.

------------------------------------------------------------------------

# Final Design Decisions

## 1. Detection Strategy

The project will use a **Hybrid Detection Architecture**.

### AI Module

Responsible for: - Detecting unknown or anomalous behaviour. - Learning
patterns from Windows Event Logs.

### Rule Engine

Responsible for: - Brute Force Detection - Privilege Escalation -
Suspicious PowerShell - New Administrator Creation - Other known attack
patterns

The outputs from both components will be combined before generating
alerts.

------------------------------------------------------------------------

## 2. Prediction Target

Primary objective:

**Binary Classification**

    Benign
            vs
    Malicious

Multi-class attack categories will be retained for:

-   Dashboard categorization
-   MITRE ATT&CK mapping
-   Threat summaries

------------------------------------------------------------------------

## 3. Learning Type

Primary approach:

**Supervised Machine Learning**

Future work may explore anomaly detection or semi-supervised learning.

------------------------------------------------------------------------

## 4. Candidate Models

The following models will be experimentally compared:

-   Random Forest
-   XGBoost
-   Decision Tree
-   Isolation Forest (for anomaly detection experiments)

The final production model will be selected based on evaluation results
rather than assumptions.

------------------------------------------------------------------------

## 5. Model Selection Criteria

Compare models using:

-   Accuracy
-   Precision
-   Recall
-   F1-Score
-   ROC-AUC
-   Training Time
-   Inference Time

Preference will be given to models that balance detection performance
and explainability.

------------------------------------------------------------------------

## 6. Explainability Strategy

Primary Explainable AI technique:

**SHAP**

Purpose:

-   Explain individual predictions.
-   Identify important features.
-   Support analyst trust.
-   Feed the Security Intelligence Layer.

Additional XAI methods are out of scope unless justified later.

------------------------------------------------------------------------

## 7. AI Output

The AI model should return:

-   Prediction
-   Confidence Score
-   SHAP Values

These outputs become the input to later modules.

------------------------------------------------------------------------

# Integration Pipeline

Windows Event Logs

↓

Preprocessing

↓

AI Model

↓

SHAP

↓

Security Intelligence Layer

↓

Risk Assessment

↓

MITRE ATT&CK Mapping

↓

Dashboard

------------------------------------------------------------------------

# Research Decisions

-   Hybrid AI + Rule-based detection is preferred over AI-only.
-   Behavioural detection is preferred over signature-based detection.
-   Model selection will be evidence-based through experimentation.
-   Explainability is a core project contribution, not an optional
    feature.

------------------------------------------------------------------------

# Deliverables

At the end of this phase:

-   AI problem definition
-   Detection strategy
-   Prediction target
-   Candidate model list
-   Evaluation strategy
-   Explainability strategy
-   Integration plan

------------------------------------------------------------------------

# Not Included

-   Data preprocessing
-   Feature engineering
-   Model training
-   Dashboard implementation

These belong to later phases.

------------------------------------------------------------------------

# Inputs

-   Dataset Selection & Analysis

# Outputs

-   Preprocessing Design
-   Model Training Phase
-   Explainability Phase

------------------------------------------------------------------------

# Notes

The final model is **not selected in this phase**.

Only the evaluation framework and selection methodology are finalized.

The chosen model must be justified experimentally during Phase 5.
