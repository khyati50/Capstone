# Phase 16 --- Frontend Dashboard Architecture

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Design an intuitive, responsive, and analyst-friendly dashboard that
visualizes security events, AI predictions, explanations, risk scores,
and attack timelines in real time.

The dashboard serves as the primary interface between the security
analyst and the detection system.

------------------------------------------------------------------------

# Why This Phase Exists

A powerful detection engine is only useful if analysts can easily
understand and investigate its results.

The frontend should transform technical outputs into actionable visual
insights.

------------------------------------------------------------------------

# Inputs

-   Backend REST APIs
-   Socket.IO Events
-   Alerts
-   Risk Scores
-   SHAP Explanations
-   Event Correlation
-   MITRE ATT&CK Mapping

------------------------------------------------------------------------

# Technology Stack

-   React.js
-   Tailwind CSS
-   Recharts
-   Axios
-   Socket.IO Client

------------------------------------------------------------------------

# Dashboard Modules

## Dashboard Home

Displays:

-   Total Alerts
-   Critical Alerts
-   Active Incidents
-   Recent Activity
-   Risk Overview

------------------------------------------------------------------------

## Alerts Page

Shows:

-   Alert ID
-   Severity
-   Prediction
-   Confidence
-   Status
-   Timestamp

Supports:

-   Search
-   Filtering
-   Sorting

------------------------------------------------------------------------

## Incident Timeline

Displays correlated attack chains in chronological order.

Information includes:

-   Event sequence
-   User
-   Host
-   Processes
-   Time progression

------------------------------------------------------------------------

## SHAP Explainability

Displays:

-   Feature importance
-   Positive contributors
-   Negative contributors
-   Explanation summary

------------------------------------------------------------------------

## Risk Assessment

Displays:

-   Risk score
-   Risk level
-   Risk trend
-   Risk history

------------------------------------------------------------------------

## MITRE ATT&CK

Displays:

-   Tactic
-   Technique
-   Technique ID
-   Related alerts

------------------------------------------------------------------------

## Simulation Panel

Controls:

-   Failed Login
-   Brute Force
-   Privilege Escalation
-   PowerShell Execution
-   Insider Threat
-   Reset Simulation
-   Switch between Live and Simulation modes

------------------------------------------------------------------------

# Real-Time Updates

Use Socket.IO to update:

-   Alerts
-   Timelines
-   Risk
-   Dashboard statistics

without requiring page refreshes.

------------------------------------------------------------------------

# Suggested Folder Structure

frontend/ ├── components/ ├── pages/ ├── hooks/ ├── services/ ├──
context/ ├── layouts/ ├── assets/ └── App.jsx

------------------------------------------------------------------------

# Deliverables

-   Dashboard UI
-   Alert Management
-   Timeline View
-   SHAP Visualization
-   MITRE Visualization
-   Simulation Controls
-   Responsive Layout

------------------------------------------------------------------------

# Common Mistakes

-   Displaying too much information at once.
-   Ignoring mobile responsiveness.
-   Mixing business logic with UI components.
-   Polling instead of using real-time updates.
-   Poor error handling for API failures.

------------------------------------------------------------------------

# Outputs

Provides an interactive interface for:

-   Security Analysts
-   Project Demonstrations
-   Threat Investigation
-   Incident Monitoring

------------------------------------------------------------------------

# Notes

The dashboard should prioritize clarity over complexity.

Every page should help an analyst answer one key question quickly:

-   What happened?
-   Why was it detected?
-   How serious is it?
-   What should I investigate next?
