# Phase 19 --- Deployment & Git Workflow

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Define a reliable deployment and collaboration workflow so the team can
develop, test, and maintain the project efficiently across multiple
computers.

This phase focuses on source control, model versioning, deployment, and
collaboration rather than new features.

------------------------------------------------------------------------

# Why This Phase Exists

The project consists of multiple independent modules developed by three
team members.

A structured workflow reduces merge conflicts, prevents accidental
overwrites, and ensures every team member works with the same codebase
and AI model.

------------------------------------------------------------------------

# Inputs

-   Integrated System (Phase 17)
-   Validated System (Phase 18)
-   Production Model
-   Project Documentation

------------------------------------------------------------------------

# Repository Structure

``` text
Enterprise-Threat-Detection/
│
├── ai/
├── backend/
├── frontend/
├── database/
├── docs/
├── models/
├── dataset/
├── scripts/
└── README.md
```

------------------------------------------------------------------------

# Git Workflow

## Branches

-   main → Stable production-ready code
-   develop → Integration branch
-   feature/`<feature-name>`{=html} → Individual development

Examples:

-   feature/preprocessing
-   feature/dashboard
-   feature/shap
-   feature/event-correlation

Merge feature branches into **develop** after review. Merge **develop**
into **main** only after successful testing.

------------------------------------------------------------------------

# Team Collaboration

Member 1 - AI pipeline - Model training - SHAP

Member 2 - Backend - Database - APIs

Member 3 - Frontend - Dashboard - Simulation UI

Everyone reviews and tests integrated features before merging.

------------------------------------------------------------------------

# Model Versioning

Store production artifacts separately.

Example:

``` text
models/
├── best_model.pkl
├── feature_names.json
├── metadata.json
├── preprocessor.pkl
└── VERSION.md
```

Track: - Model version - Dataset version - Training date - Algorithm -
Evaluation metrics

------------------------------------------------------------------------

# Multi-PC Workflow

Training Machine

-   Train model
-   Save artifacts
-   Commit or securely share model files

Application Machine

-   Pull latest code
-   Load production model
-   Run backend and frontend

No retraining should occur during deployment.

------------------------------------------------------------------------

# Deployment Checklist

-   Backend configured
-   Database migrated
-   Production model available
-   Environment variables configured
-   Dependencies installed
-   Dashboard connected
-   Simulation mode verified
-   Live monitoring verified

------------------------------------------------------------------------

# Configuration Management

Use environment variables for:

-   Database credentials
-   API ports
-   JWT secrets
-   Model path
-   Socket configuration

Do not hardcode secrets into the repository.

------------------------------------------------------------------------

# Deliverables

-   Git workflow documentation
-   Repository structure
-   Deployment checklist
-   Model versioning strategy
-   Collaboration guide

------------------------------------------------------------------------

# Common Mistakes

-   Working directly on the main branch
-   Mixing experimental and production models
-   Hardcoding configuration values
-   Deploying untested code
-   Ignoring merge conflicts

------------------------------------------------------------------------

# Outputs

A reproducible development and deployment workflow that allows the
project to be built, tested, and demonstrated consistently on different
machines.

------------------------------------------------------------------------

# Notes

The deployment process should prioritize reproducibility. Any team
member should be able to clone the repository, configure the
environment, load the approved production model, and run the complete
application using the documented setup procedure.
