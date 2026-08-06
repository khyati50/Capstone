"""Scenario-Level Data Splitting Module.

Performs scenario-level splitting (70% train / 15% val / 15% test) to keep entire
attack sequences intact in a single split, preventing temporal data leakage.
"""

from typing import Tuple
import numpy as np
import pandas as pd


def scenario_level_split(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_state: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split DataFrame into Train, Validation, and Test sets by scenario_id.

    Args:
        df: Input DataFrame containing 'scenario_id' column.
        train_ratio: Proportion for training set.
        val_ratio: Proportion for validation set.
        test_ratio: Proportion for test set.
        random_state: Random seed for reproducibility.

    Returns:
        Tuple of (train_df, val_df, test_df).
    """
    if df.empty or "scenario_id" not in df.columns:
        return df, pd.DataFrame(), pd.DataFrame()

    scenarios = df["scenario_id"].unique()
    np.random.seed(random_state)
    shuffled_scenarios = np.random.permutation(scenarios)

    n_total = len(shuffled_scenarios)
    n_train = int(n_total * train_ratio)
    n_val = int(n_total * val_ratio)

    train_scenarios = shuffled_scenarios[:n_train]
    val_scenarios = shuffled_scenarios[n_train : n_train + n_val]
    test_scenarios = shuffled_scenarios[n_train + n_val :]

    train_df = df[df["scenario_id"].isin(train_scenarios)].copy().reset_index(drop=True)
    val_df = df[df["scenario_id"].isin(val_scenarios)].copy().reset_index(drop=True)
    test_df = df[df["scenario_id"].isin(test_scenarios)].copy().reset_index(drop=True)

    return train_df, val_df, test_df
