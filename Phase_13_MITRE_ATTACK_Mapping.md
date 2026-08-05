# Phase 13 --- MITRE ATT&CK Mapping

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Map detected incidents to the MITRE ATT&CK framework so analysts
understand **how an attacker is operating**, not just that an alert
occurred.

This module provides standardized threat context using ATT&CK tactics
and techniques.

------------------------------------------------------------------------

# Why This Phase Exists

Raw Windows Event IDs are difficult to interpret.

Example:

-   Event ID 4688

alone tells an analyst very little.

Mapping it to:

-   **T1059 -- Command and Scripting Interpreter**

immediately provides meaningful security context.

------------------------------------------------------------------------

# Inputs

-   Hybrid Detection Output
-   Event Correlation
-   Risk Assessment
-   Windows Event Metadata
-   Rule Engine Results

------------------------------------------------------------------------

# Mapping Strategy

Use a predefined mapping between:

-   Windows Event IDs
-   Rule Engine detections
-   Attack chains

and corresponding:

-   MITRE Tactic
-   MITRE Technique
-   Technique ID

The mapping should be stored separately from application logic.

------------------------------------------------------------------------

# Example Mapping

  Windows Event       MITRE Technique
  ------------------- ---------------------------------------------
  4625                T1110 -- Brute Force
  4688 (PowerShell)   T1059 -- Command & Scripting Interpreter
  4672                T1078 -- Valid Accounts (Context Dependent)
  7045                T1543 -- Create or Modify System Process

> The exact mapping should be validated during implementation.

------------------------------------------------------------------------

# Multiple Technique Support

One incident may map to multiple techniques.

Example:

Failed Login ↓

Successful Login ↓

PowerShell

↓

Privilege Escalation

Produces:

-   T1110
-   T1078
-   T1059

instead of only one technique.

------------------------------------------------------------------------

# Dashboard Integration

Display:

-   ATT&CK Technique ID
-   Technique Name
-   Tactic
-   Related Events
-   Incident Timeline

Allow analysts to navigate from an alert to its ATT&CK context.

------------------------------------------------------------------------

# Deliverables

-   MITRE mapping table
-   Mapping engine
-   ATT&CK integration documentation
-   Dashboard visualization data

------------------------------------------------------------------------

# Common Mistakes

-   Hardcoding mappings throughout the codebase.
-   Mapping every Event ID directly without context.
-   Ignoring attack chains.
-   Displaying only technique IDs without descriptions.

------------------------------------------------------------------------

# Outputs

Provides standardized threat intelligence to:

-   SOC Dashboard
-   Investigation Workflow
-   Reports
-   Incident Summaries

------------------------------------------------------------------------

# Research Contribution

The MITRE ATT&CK integration improves the interpretability and
operational value of the system by translating low-level Windows
security events into a globally recognized attack framework, making the
dashboard more useful for security analysts and incident response.
