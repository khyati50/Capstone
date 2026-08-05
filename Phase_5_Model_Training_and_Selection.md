# Phase 5 --- Model Training & Selection

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat
> Detection and Investigation Dashboard

------------------------------------------------------------------------

# Objective

Train, compare, and select the best machine learning model for detecting
malicious Windows event log activity.

The purpose of this phase is **not** to prove one model is best
beforehand, but to experimentally evaluate multiple candidates and
select the final production model based on evidence.

------------------------------------------------------------------------

# Inputs

-   Processed dataset (Phase 4)
-   Train / Validation / Test split
-   Feature engineered dataset
-   AI Problem Definition (Phase 3)

------------------------------------------------------------------------

# Why This Phase Exists

Different machine learning algorithms perform differently depending on
the dataset.

Rather than assuming a model is the best choice, we will compare
multiple algorithms using the same data and evaluation methodology.

------------------------------------------------------------------------

# Candidate Models

The following models will be evaluated:

-   Random Forest
-   XGBoost
-   Decision Tree
-   Isolation Forest (anomaly detection comparison)

Additional models may be included if supported by research.

------------------------------------------------------------------------

# Training Strategy

For every model:

1.  Load the processed training dataset.
2.  Train using identical feature sets.
3.  Tune important hyperparameters.
4.  Validate using the validation set.
5.  Record all evaluation metrics.
6.  Compare results objectively.

------------------------------------------------------------------------

# Evaluation Metrics

Each model will be evaluated using:

-   Accuracy
-   Precision
-   Recall
-   F1-Score
-   ROC-AUC (where applicable)
-   Confusion Matrix
-   Training Time
-   Inference Time

The chosen model should balance performance, explainability, and
computational efficiency.

------------------------------------------------------------------------

# Hyperparameter Tuning

Possible approaches:

-   Grid Search
-   Random Search

The same tuning strategy should be applied consistently across candidate
models.

------------------------------------------------------------------------

# Model Comparison

Create a comparison table including:

-   Performance metrics
-   Training time
-   Prediction speed
-   Advantages
-   Limitations
-   SHAP compatibility

The final selection must be justified using experimental results.

------------------------------------------------------------------------

# Production Model

After evaluation:

-   Select the best-performing model.
-   Retrain (if required) on the final training data.
-   Save the model.

Expected artifacts:

-   best_model.pkl
-   feature_names.json
-   metadata.json
-   preprocessor.pkl (if applicable)

------------------------------------------------------------------------

# Folder Structure

``` text
ai/
├── models/
├── training/
├── evaluation/
├── saved_models/
└── experiments/
```

------------------------------------------------------------------------

# Deliverables

-   Trained candidate models
-   Evaluation report
-   Model comparison table
-   Selected production model
-   Saved model artifacts

------------------------------------------------------------------------

# Common Mistakes to Avoid

-   Choosing a model before experimentation.
-   Evaluating on the test set during tuning.
-   Ignoring inference time.
-   Not documenting hyperparameters.
-   Saving a model without recording preprocessing information.

------------------------------------------------------------------------

# Not Included

-   SHAP analysis
-   Dashboard integration
-   Backend integration
-   Real-time monitoring

These will be handled in later phases.

------------------------------------------------------------------------

# Outputs

This phase produces the production model that will be used in:

-   SHAP Explainability
-   Hybrid Detection
-   Backend Integration
-   Real-Time Prediction Pipeline

------------------------------------------------------------------------

# Notes

The production model should remain unchanged during application
development.

Retraining should occur only when a new dataset or improved methodology
is introduced.

This ensures reproducibility, stable APIs, and consistent evaluation
throughout the project.
