# Phase 12 --- Risk Assessment Engine

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Prioritize detected incidents by calculating a dynamic risk score
instead of treating every alert equally.

The Risk Assessment Engine combines outputs from the AI model, rule
engine, SHAP explanations, and event correlation to estimate the overall
severity of an incident.

------------------------------------------------------------------------

# Why This Phase Exists

Not every suspicious event represents the same level of danger.

Examples:

-   One failed login attempt → Low Risk
-   Twenty failed logins followed by a successful login → High Risk
-   Successful login followed by privilege escalation and PowerShell
    execution → Critical Risk

The dashboard should help analysts focus on the most important incidents
first.

------------------------------------------------------------------------

# Inputs

-   Hybrid Detection Output
-   AI Confidence Score
-   Rule Engine Results
-   SHAP Explanations
-   Event Correlation & Attack Timeline

------------------------------------------------------------------------

# Risk Factors

The overall score may consider:

-   AI confidence
-   Number of triggered rules
-   Attack severity
-   Event correlation strength
-   Sensitive Event IDs
-   Number of affected hosts
-   Number of affected users
-   Frequency of suspicious events

The exact weighting should be determined experimentally and documented.

------------------------------------------------------------------------

# Risk Levels

Example classification:

-   Low
-   Medium
-   High
-   Critical

Thresholds should be configurable rather than hardcoded.

------------------------------------------------------------------------

# Dynamic Risk Scoring

Risk should update whenever new events are correlated.

Example:

Failed Login ↓

Successful Login

↓

Privilege Escalation

↓

PowerShell Execution

↓

Risk increases as the attack progresses.

------------------------------------------------------------------------

# Dashboard Integration

Display:

-   Current Risk Score
-   Risk Level
-   Score Breakdown
-   Trend (Increasing / Stable / Decreasing)

------------------------------------------------------------------------

# Deliverables

-   Risk scoring algorithm
-   Risk level classification
-   Risk calculation documentation
-   Dashboard risk widgets

------------------------------------------------------------------------

# Common Mistakes

-   Giving every alert the same importance.
-   Using fixed scores without justification.
-   Ignoring AI confidence.
-   Ignoring correlated attack chains.
-   Making risk scores impossible to interpret.

------------------------------------------------------------------------

# Outputs

The Risk Assessment Engine provides prioritized incidents to:

-   MITRE ATT&CK Mapping
-   SOC Dashboard
-   Analyst Investigation Workflow

------------------------------------------------------------------------

# Research Contribution

Instead of displaying only alerts, the system prioritizes incidents
using multiple evidence sources, helping analysts focus on the threats
that are most likely to require immediate investigation.
