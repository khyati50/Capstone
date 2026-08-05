# Phase 15 --- Database Design

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Design a scalable and normalized database that stores logs, predictions,
alerts, correlated incidents, MITRE mappings, and investigation data.

The database should support real-time querying, dashboard visualization,
and future project expansion.

------------------------------------------------------------------------

# Why This Phase Exists

The database is the central repository for all processed information.

It should not store only raw logs---it should also maintain the complete
investigation lifecycle.

------------------------------------------------------------------------

# Inputs

-   Windows Event Logs
-   AI Predictions
-   Rule Engine Results
-   SHAP Explanations
-   Event Correlation
-   Risk Assessment
-   MITRE ATT&CK Mapping

------------------------------------------------------------------------

# Database Technology

Primary Database:

-   MySQL

Reason:

-   Relational structure
-   ACID compliance
-   Easy integration with Node.js
-   Suitable for structured security data

------------------------------------------------------------------------

# Proposed Tables

## users

Stores analyst accounts.

Fields: - user_id - name - email - password_hash - role - created_at

------------------------------------------------------------------------

## raw_logs

Stores parsed Windows events.

Fields: - log_id - timestamp - event_id - provider - hostname -
username - source_ip - process_name - scenario_id

------------------------------------------------------------------------

## predictions

Stores AI inference results.

Fields: - prediction_id - log_id - prediction - confidence -
model_version - created_at

------------------------------------------------------------------------

## alerts

Stores unified alerts after hybrid detection.

Fields: - alert_id - prediction_id - severity - status - summary -
explanation

------------------------------------------------------------------------

## incidents

Represents correlated attack timelines.

Fields: - incident_id - start_time - end_time - risk_level - status

------------------------------------------------------------------------

## incident_events

Maps logs to incidents.

Fields: - incident_id - log_id

------------------------------------------------------------------------

## mitre_mapping

Fields: - mapping_id - incident_id - tactic - technique - technique_id

------------------------------------------------------------------------

## risk_scores

Fields: - risk_id - incident_id - score - level - calculated_at

------------------------------------------------------------------------

# Relationships

users ↓

alerts

raw_logs ↓

predictions ↓

alerts ↓

incidents ↓

risk_scores

incidents ↓

mitre_mapping

incidents ↓

incident_events ↓

raw_logs

------------------------------------------------------------------------

# Database Principles

-   Normalize data
-   Avoid duplicate records
-   Use foreign keys
-   Index frequently queried fields
-   Maintain audit timestamps

------------------------------------------------------------------------

# Folder Structure

database/ ├── schema/ ├── migrations/ ├── seeders/ └── diagrams/

------------------------------------------------------------------------

# Deliverables

-   ER Diagram
-   SQL Schema
-   Migration Scripts
-   Seed Data
-   Database Documentation

------------------------------------------------------------------------

# Common Mistakes

-   Storing repeated information
-   Missing foreign keys
-   No indexing
-   Mixing raw logs with processed alerts
-   Hardcoding values in the schema

------------------------------------------------------------------------

# Outputs

Provides persistent storage for:

-   Backend APIs
-   Dashboard
-   Reports
-   Investigation Workflow

------------------------------------------------------------------------

# Notes

The schema should remain modular so additional log sources, new AI
models, or future features can be integrated without redesigning the
database.
