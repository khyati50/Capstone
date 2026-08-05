# Phase 4 --- Data Preprocessing & Feature Engineering

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Convert the raw Atomic-EVTX dataset into a clean, structured,
machine-learning-ready dataset while preserving attack behavior and
event relationships.

This phase prepares the data for model training but **does not train any
model**.

------------------------------------------------------------------------

# Why This Phase Exists

Raw Windows Event Logs contain:

-   Noise
-   Missing fields
-   Nested JSON
-   Inconsistent formats
-   Duplicate information

Machine learning models cannot learn effectively from raw log files.

The goal is to extract meaningful security information without losing
the context needed for event correlation and explainability.

------------------------------------------------------------------------

# Inputs

-   Atomic-EVTX Dataset
-   Dataset Analysis Report (Phase 2)
-   AI Problem Definition (Phase 3)

------------------------------------------------------------------------

# Design Decisions

## 1. Parse Raw Logs

Extract required information from JSON/EVTX.

Typical fields include:

-   Timestamp
-   Event ID
-   Provider
-   Computer Name
-   User
-   Process Name
-   Parent Process
-   Command Line
-   Source IP
-   Destination IP
-   Logon Type
-   Channel

------------------------------------------------------------------------

## 2. Keep Security-Relevant Events

Start with the curated Event ID list defined in Phase 2.

After Exploratory Data Analysis (EDA), refine the list if required.

The goal is to reduce noise while preserving attack chains.

------------------------------------------------------------------------

## 3. Handle Missing Values

-   Identify missing fields
-   Remove unusable records only when necessary
-   Replace or encode missing values where appropriate
-   Document every preprocessing decision

------------------------------------------------------------------------

## 4. Remove Duplicate Events

Duplicate log entries should be removed only if they are true
duplicates.

Do not remove repeated events that are part of an attack sequence.

------------------------------------------------------------------------

## 5. Feature Engineering

Create meaningful features such as:

-   Failed login count
-   Time since previous event
-   Process execution frequency
-   Privilege escalation indicators
-   PowerShell usage
-   Session duration
-   User activity statistics

Feature engineering should be guided by cybersecurity knowledge rather
than arbitrary transformations.

------------------------------------------------------------------------

## 6. Categorical Encoding

Convert categorical values into machine-learning-compatible
representations.

Examples:

-   Event ID
-   Logon Type
-   Process Name
-   User Account
-   Provider

The encoding method will depend on the selected model.

------------------------------------------------------------------------

## 7. Numerical Features

Normalize or scale features only if required by the selected algorithm.

Tree-based models generally do not require feature scaling.

------------------------------------------------------------------------

## 8. Dataset Splitting

Perform scenario-level splitting.

Recommended split:

-   Train: 70%
-   Validation: 15%
-   Test: 15%

Never split individual events from the same attack scenario across
different datasets.

------------------------------------------------------------------------

## 9. Preserve Event Relationships

Maintain:

-   Scenario ID
-   Event order
-   Timestamp sequence

These are required for:

-   Event Correlation
-   Attack Timeline
-   Risk Assessment

------------------------------------------------------------------------

# Exploratory Data Analysis (EDA)

Before preprocessing, perform EDA to understand:

-   Event ID frequency
-   Missing values
-   Attack distribution
-   Benign vs malicious ratio
-   Class imbalance
-   Timestamp distribution
-   Top users
-   Top processes
-   Attack category distribution

------------------------------------------------------------------------

# Expected Folder Structure

``` text
ai/
├── raw_data/
├── processed_data/
├── notebooks/
├── preprocessing/
├── feature_engineering/
└── dataset_reports/
```

------------------------------------------------------------------------

# Deliverables

-   Clean dataset
-   Feature engineered dataset
-   Train / Validation / Test datasets
-   Feature list
-   Data dictionary
-   Preprocessing documentation

------------------------------------------------------------------------

# Common Mistakes to Avoid

-   Random event-level train/test splitting
-   Removing events that break attack chains
-   Data leakage
-   Over-filtering useful security events
-   Performing feature engineering using future information

------------------------------------------------------------------------

# Not Included

-   Model training
-   Hyperparameter tuning
-   SHAP analysis
-   Dashboard implementation

------------------------------------------------------------------------

# Outputs

This phase produces the final datasets that will be used in Phase 5
(Model Training & Selection).

------------------------------------------------------------------------

# Notes

Every preprocessing step must be reproducible and documented.

The preprocessing pipeline should be reusable for both:

-   Live Windows Event Logs
-   Simulation Mode

This ensures consistent data preparation regardless of the log source.
