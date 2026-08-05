# Phase 18 --- Testing & Evaluation

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Verify that every component of the system works correctly, integrates
successfully, and meets the project's functional, machine learning, and
usability requirements.

Testing should validate not only the AI model, but the complete
end-to-end cybersecurity platform.

------------------------------------------------------------------------

# Why This Phase Exists

A trained model alone does not guarantee a successful system.

This phase evaluates:

-   Machine learning performance
-   Backend functionality
-   Frontend functionality
-   System integration
-   Real-time behaviour
-   User experience

------------------------------------------------------------------------

# Inputs

-   Integrated System (Phase 17)
-   Production Model
-   Atomic-EVTX Dataset
-   Simulation Engine
-   Live Monitoring Module

------------------------------------------------------------------------

# Testing Levels

## 1. Unit Testing

Verify individual modules independently.

Examples:

-   Prediction Service
-   Rule Engine
-   Risk Calculation
-   Event Correlation
-   MITRE Mapping

------------------------------------------------------------------------

## 2. Integration Testing

Verify communication between modules.

Examples:

-   Backend ↔ Prediction Service
-   Backend ↔ Database
-   Backend ↔ Dashboard
-   Simulation ↔ AI Pipeline

------------------------------------------------------------------------

## 3. Functional Testing

Verify major user workflows.

Examples:

-   Login
-   View Alerts
-   Run Simulation
-   View Timeline
-   Inspect SHAP Explanation
-   View MITRE Mapping

------------------------------------------------------------------------

## 4. Machine Learning Evaluation

Evaluate the final model using:

-   Accuracy
-   Precision
-   Recall
-   F1-Score
-   ROC-AUC
-   Confusion Matrix

Document all results.

------------------------------------------------------------------------

## 5. Performance Testing

Measure:

-   Prediction latency
-   API response time
-   Dashboard update speed
-   Database query time
-   Memory usage

------------------------------------------------------------------------

## 6. Usability Testing

Verify that analysts can:

-   Understand alerts
-   Interpret explanations
-   Navigate the dashboard
-   Investigate incidents efficiently

------------------------------------------------------------------------

# Test Scenarios

Recommended simulations:

-   Failed Login
-   Brute Force
-   Privilege Escalation
-   PowerShell Execution
-   Insider Threat

Verify that each scenario flows correctly through the complete pipeline.

------------------------------------------------------------------------

# Success Criteria

The system should:

-   Produce consistent predictions
-   Generate understandable explanations
-   Correlate related events
-   Calculate meaningful risk scores
-   Display live dashboard updates
-   Map incidents to MITRE ATT&CK

------------------------------------------------------------------------

# Deliverables

-   Test Plan
-   Test Cases
-   Evaluation Metrics
-   Performance Report
-   Bug Report
-   Final Validation Report

------------------------------------------------------------------------

# Common Mistakes

-   Testing only the AI model
-   Ignoring integration issues
-   Measuring only accuracy
-   Skipping usability evaluation
-   Testing with only one scenario

------------------------------------------------------------------------

# Outputs

A validated cybersecurity platform ready for deployment and research
publication.

------------------------------------------------------------------------

# Notes

All evaluation results should be reproducible and included in the final
project report and research paper. Any limitations discovered during
testing should be documented along with proposed future improvements.
