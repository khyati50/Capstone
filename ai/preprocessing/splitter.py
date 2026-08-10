"""Scenario-Level Data Splitting Module.

Performs scenario-level splitting using GroupShuffleSplit from sklearn.model_selection
to keep entire attack sequences intact in a single split, preventing temporal data leakage.
"""

from typing import Tuple
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit


def scenario_level_split(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_state: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split DataFrame into Train, Validation, and Test sets by scenario_id using GroupShuffleSplit.

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

    # Step 1: First GroupShuffleSplit to separate Train (train_ratio) from Temp (val + test)
    temp_ratio = val_ratio + test_ratio
    gss1 = GroupShuffleSplit(n_splits=1, test_size=temp_ratio, random_state=random_state)
    train_idx, temp_idx = next(gss1.split(df, groups=df["scenario_id"]))

    train_df = df.iloc[train_idx].copy().reset_index(drop=True)
    temp_df = df.iloc[temp_idx].copy().reset_index(drop=True)

    # Step 2: Second GroupShuffleSplit on Temp set to split into Val and Test
    val_prop_of_temp = val_ratio / temp_ratio
    gss2 = GroupShuffleSplit(n_splits=1, test_size=(1.0 - val_prop_of_temp), random_state=random_state)
    val_idx, test_idx = next(gss2.split(temp_df, groups=temp_df["scenario_id"]))

    val_df = temp_df.iloc[val_idx].copy().reset_index(drop=True)
    test_df = temp_df.iloc[test_idx].copy().reset_index(drop=True)

    return train_df, val_df, test_df
