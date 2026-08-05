# Phase 6 --- Prediction Service & Model Deployment

> Project: Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

## Objective

Convert the trained machine learning model into a reusable prediction
service that can be integrated with the backend, simulation engine, and
live monitoring pipeline.

## Why This Phase Exists

Training and prediction should be separated. The trained model becomes
the production model and is only used for inference.

## Inputs

-   best_model.pkl
-   feature_names.json
-   metadata.json
-   preprocessor.pkl (if required)

## Workflow

Windows Event → Feature Extraction → Load Production Model → Prediction
→ Confidence Score → JSON Response

## Responsibilities

### Load Model

-   Load once during startup.
-   Never retrain during application execution.

### Prediction Service

Input: - Processed event - Feature vector

Output: - Prediction - Confidence - Metadata

### Artifact Management

models/ - best_model.pkl - feature_names.json - metadata.json -
preprocessor.pkl

### Multi-PC Workflow

Training PC - Train model - Save artifacts - Push artifacts

Application PC - Pull artifacts - Load model - Perform inference

### Versioning

Maintain model versions and record: - Dataset version - Algorithm -
Hyperparameters - Evaluation metrics - Training date

## Folder Structure

ai/ - models/ - inference/ - prediction_service/ - metadata/

## Deliverables

-   Production model
-   Prediction service
-   Model artifacts
-   Deployment guide

## Common Mistakes

-   Retraining during inference
-   Mixing training and prediction code
-   Different preprocessing on different machines
-   Missing model version information

## Outputs

A stable prediction service used by: - Backend - Simulation Engine -
Real-Time Monitoring - SHAP Explainability

## Notes

The application should behave identically regardless of which computer
trained the model, provided the same model artifacts are used.
