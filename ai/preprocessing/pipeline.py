"""End-to-End Preprocessing Pipeline Orchestrator."""

from pathlib import Path
from typing import Tuple
import pandas as pd

from .parser import parse_all_scenarios
from .feature_engineering import engineer_features
from .splitter import scenario_level_split


def run_preprocessing_pipeline(
    dataset_root: Path,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Execute parsing, feature engineering, and scenario splitting.

    Args:
        dataset_root: Path to raw dataset folder.
        train_ratio: Proportion for train split.
        val_ratio: Proportion for validation split.
        test_ratio: Proportion for test split.

    Returns:
        Tuple of (train_df, val_df, test_df).
    """
    print(f"Loading raw logs from {dataset_root}...")
    parsed_df = parse_all_scenarios(dataset_root)
    if parsed_df.empty:
        print("Warning: No records found during parsing.")
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    print(f"Parsed {len(parsed_df)} log records. Engineering features...")
    featured_df = engineer_features(parsed_df)

    print("Splitting datasets by scenario ID...")
    train_df, val_df, test_df = scenario_level_split(
        featured_df, train_ratio=train_ratio, val_ratio=val_ratio, test_ratio=test_ratio
    )

    print(f"Pipeline Complete: Train={len(train_df)}, Val={len(val_df)}, Test={len(test_df)}")
    return train_df, val_df, test_df
