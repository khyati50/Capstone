# Phase 7 --- Real-Time Monitoring & Simulation Engine

> Project: Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Build a real-time event ingestion pipeline capable of processing both:

-   Live Windows Event Logs
-   Simulated attack events

Both modes must use the **same detection pipeline**, ensuring identical
AI analysis regardless of the event source.

------------------------------------------------------------------------

# Why This Phase Exists

A real SOC continuously receives new events.

However, for development, testing, and demonstrations, generating real
attacks is difficult.

To solve this, the system supports two operating modes:

1.  Live Monitoring
2.  Simulation Mode

The only difference between the two modes is the source of the events.

------------------------------------------------------------------------

# Inputs

-   Prediction Service (Phase 6)
-   Windows Event Logs
-   Simulation Engine

------------------------------------------------------------------------

# System Architecture

``` text
                 +----------------+
                 | Live Log Reader|
                 +----------------+
                          |
                          |
                 +----------------+
                 | Simulation UI  |
                 +----------------+
                          |
                          ▼
                 Unified Event Queue
                          │
                          ▼
                Feature Extraction
                          │
                          ▼
                Prediction Service
                          │
                          ▼
                 AI Prediction
```

------------------------------------------------------------------------

# Live Monitoring Mode

Read Windows Event Logs continuously.

Possible sources:

-   Security Log
-   System Log
-   Application Log
-   Sysmon
-   PowerShell

Responsibilities

-   Detect newly generated events
-   Convert logs into structured format
-   Send events to the prediction service

------------------------------------------------------------------------

# Simulation Mode

A built-in simulation engine generates realistic Windows security
events.

Purpose

-   Development
-   Testing
-   Project demonstrations
-   Repeatable experiments

------------------------------------------------------------------------

# Simulation Control Panel

Example actions:

-   Failed Login
-   Successful Login
-   Brute Force Attack
-   Privilege Escalation
-   PowerShell Execution
-   New Administrator Created
-   Insider Threat
-   Malware Execution
-   Clear Simulation

------------------------------------------------------------------------

# Event Flow

Simulation Button

↓

Generate Windows Event

↓

Preprocessing

↓

Prediction Service

↓

AI Prediction

↓

Backend

↓

Dashboard

Exactly the same pipeline is used for live monitoring.

------------------------------------------------------------------------

# Real-Time Updates

The dashboard should update automatically whenever:

-   New log arrives
-   New alert is generated
-   Risk score changes
-   Event timeline changes

Suggested technology:

-   Socket.IO

------------------------------------------------------------------------

# Design Principles

-   One processing pipeline
-   Two event sources
-   No duplicate detection logic
-   Simulation should behave like real events
-   Event format should remain identical

------------------------------------------------------------------------

# Deliverables

-   Live log listener
-   Simulation engine
-   Simulation control panel
-   Unified event pipeline
-   Real-time update mechanism

------------------------------------------------------------------------

# Common Mistakes

-   Maintaining separate pipelines for simulation and live mode.
-   Generating unrealistic events.
-   Bypassing preprocessing during simulation.
-   Hardcoding attack results.

------------------------------------------------------------------------

# Outputs

This phase provides real-time events to:

-   Hybrid Detection Engine
-   SHAP Explainability
-   Event Correlation
-   Risk Assessment
-   Dashboard

------------------------------------------------------------------------

# Notes

Simulation mode is a testing and demonstration feature---not a
replacement for live monitoring.

By ensuring both modes share the same processing pipeline, the system
remains consistent, easier to test, and closer to real-world deployment.
