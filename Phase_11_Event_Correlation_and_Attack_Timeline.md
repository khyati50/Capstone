# Phase 11 --- Event Correlation & Attack Timeline

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Correlate individual Windows security events into meaningful attack
chains instead of analyzing each event in isolation.

This phase reconstructs the sequence of attacker actions, helping
analysts understand **what happened, in what order, and how the attack
progressed.**

------------------------------------------------------------------------

# Why This Phase Exists

A single Windows Event ID rarely tells the complete story.

Example:

-   4625 (Failed Login)

by itself is not necessarily suspicious.

However,

4625 → 4625 → 4624 → 4672 → 4688

strongly suggests a possible attack sequence.

This phase converts isolated events into investigation timelines.

------------------------------------------------------------------------

# Inputs

-   Windows Event Logs
-   Hybrid Detection Output
-   SHAP Explanations
-   Security Intelligence Layer

------------------------------------------------------------------------

# Goals

-   Link related events
-   Preserve event order
-   Detect attack chains
-   Reduce alert fatigue
-   Provide investigation context

------------------------------------------------------------------------

# Correlation Strategy

Events may be linked using:

-   Timestamp
-   User Account
-   Host Name
-   Session ID
-   Process ID
-   Parent Process
-   Source IP
-   Destination IP

Multiple conditions may be required before events are considered part of
the same incident.

------------------------------------------------------------------------

# Example Attack Chain

    4625  Failed Login
            ↓
    4625  Failed Login
            ↓
    4624  Successful Login
            ↓
    4672  Special Privileges Assigned
            ↓
    4688  PowerShell Process Created

Timeline Summary:

-   Repeated authentication failures
-   Successful compromise
-   Privilege escalation
-   Command execution

------------------------------------------------------------------------

# Timeline Generation

For every incident generate:

-   Timeline ID
-   Start Time
-   End Time
-   Ordered Events
-   Related User
-   Related Host
-   Related Processes
-   Severity

------------------------------------------------------------------------

# Dashboard Integration

Display:

-   Interactive attack timeline
-   Chronological event list
-   Correlated evidence
-   Timeline filtering

------------------------------------------------------------------------

# Deliverables

-   Event correlation engine
-   Timeline generator
-   Correlation rules
-   Timeline visualization data

------------------------------------------------------------------------

# Common Mistakes

-   Treating every event independently
-   Ignoring timestamps
-   Breaking attack sequences during preprocessing
-   Correlating unrelated events

------------------------------------------------------------------------

# Outputs

Provides enriched incidents to:

-   Risk Assessment Engine
-   MITRE ATT&CK Mapping
-   SOC Dashboard

------------------------------------------------------------------------

# Research Contribution

Rather than displaying isolated alerts, the system reconstructs attack
progression, allowing analysts to understand the complete incident
lifecycle and investigate threats more efficiently.
