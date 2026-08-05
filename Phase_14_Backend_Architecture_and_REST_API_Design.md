# Phase 14 --- Backend Architecture & REST API Design

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Develop a scalable backend that connects every project module into a
single application.

The backend is responsible for receiving events, communicating with the
AI prediction service, storing data, and serving information to the
React dashboard through REST APIs.

------------------------------------------------------------------------

# Why This Phase Exists

The AI model, simulation engine, database, and dashboard should never
communicate directly.

The backend acts as the central orchestration layer.

------------------------------------------------------------------------

# Inputs

-   Prediction Service
-   Hybrid Detection Engine
-   Event Correlation
-   Risk Assessment
-   MITRE ATT&CK Mapping
-   Simulation Engine
-   Live Windows Event Logs

------------------------------------------------------------------------

# Responsibilities

## Event Management

-   Receive live events
-   Receive simulated events
-   Validate incoming data
-   Forward events for prediction

------------------------------------------------------------------------

## AI Integration

The backend sends processed features to the Prediction Service and
receives:

-   Prediction
-   Confidence
-   SHAP data

------------------------------------------------------------------------

## Database Operations

Store and retrieve:

-   Logs
-   Alerts
-   Predictions
-   Risk Scores
-   Correlated Incidents
-   MITRE Mapping

------------------------------------------------------------------------

## REST APIs

### Authentication

-   POST /api/auth/login
-   POST /api/auth/register

### Events

-   POST /api/events
-   GET /api/events

### Alerts

-   GET /api/alerts
-   GET /api/alerts/:id

### Timeline

-   GET /api/timeline/:incidentId

### Risk

-   GET /api/risk

### MITRE

-   GET /api/mitre

### Simulation

-   POST /api/simulate/event
-   POST /api/simulate/scenario
-   POST /api/simulate/reset

------------------------------------------------------------------------

# Backend Workflow

Client

↓

REST API

↓

Validation

↓

Prediction Service

↓

Hybrid Detection

↓

Database

↓

Response

------------------------------------------------------------------------

# Real-Time Updates

Use Socket.IO to push:

-   New alerts
-   Risk updates
-   Timeline updates
-   Dashboard notifications

without refreshing the page.

------------------------------------------------------------------------

# Folder Structure

``` text
backend/
├── controllers/
├── routes/
├── middleware/
├── services/
├── models/
├── sockets/
├── utils/
├── config/
└── server.js
```

------------------------------------------------------------------------

# Deliverables

-   Express server
-   REST APIs
-   Socket.IO integration
-   Backend documentation
-   API specification

------------------------------------------------------------------------

# Common Mistakes

-   Business logic inside routes
-   Tight coupling with AI code
-   Returning inconsistent JSON
-   Missing validation
-   No centralized error handling

------------------------------------------------------------------------

# Outputs

Provides data to:

-   React Dashboard
-   Database
-   Simulation Engine
-   Reporting Module

------------------------------------------------------------------------

# Notes

The backend should remain independent of the AI implementation.

It should communicate with the Prediction Service through a well-defined
interface, making it possible to update or replace the ML model without
changing the backend architecture.
