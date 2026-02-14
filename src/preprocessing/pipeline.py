"""Data preprocessing pipeline for IDS datasets."""

import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.preprocessing import StandardScaler, LabelEncoder
from typing import Optional, Tuple

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config.settings import PROCESSED_DATA_DIR, RANDOM_STATE


class PreprocessingPipeline:
    """Clean, normalize, and prepare data for ML models."""

    def __init__(self, random_state: int = RANDOM_STATE):
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.categorical_columns: list = []
        self.numerical_columns: list = []
        self._fitted = False

    def _identify_columns(self, df: pd.DataFrame) -> None:
        """Identify categorical vs numerical columns."""
        self.categorical_columns = df.select_dtypes(
            include=["object", "category"]
        ).columns.tolist()
        self.numerical_columns = df.select_dtypes(
            include=[np.number]
        ).columns.tolist()

        # Exclude label from numerical if present
        if "label" in self.numerical_columns:
            self.numerical_columns.remove("label")

    def _handle_missing(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle missing values."""
        df = df.copy()

        # For numerical: fill with median
        for col in self.numerical_columns:
            if col in df.columns and df[col].isna().any():
                df[col] = df[col].fillna(df[col].median())

        # For categorical: fill with mode or 'Unknown'
        for col in self.categorical_columns:
            if col in df.columns and df[col].isna().any():
                mode_val = df[col].mode()
                df[col] = df[col].fillna(
                    mode_val.iloc[0] if len(mode_val) > 0 else "Unknown"
                )

        return df

    def _handle_infinite(self, df: pd.DataFrame) -> pd.DataFrame:
        """Replace inf values with np.nan then impute."""
        df = df.replace([np.inf, -np.inf], np.nan)
        for col in self.numerical_columns:
            if col in df.columns:
                df[col] = df[col].fillna(df[col].median())
        return df

    def _clip_outliers(
        self,
        df: pd.DataFrame,
        columns: Optional[list] = None,
        lower: float = 0.01,
        upper: float = 0.99
    ) -> pd.DataFrame:
        """Clip outliers to percentiles."""
        cols = columns or self.numerical_columns
        df = df.copy()
        for col in cols:
            if col not in df.columns:
                continue
            lo = df[col].quantile(lower)
            hi = df[col].quantile(upper)
            df[col] = df[col].clip(lo, hi)
        return df

    def _encode_labels(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        """Encode label column for classification."""
        if "label" not in df.columns:
            return df

        df = df.copy()
        labels = df["label"].astype(str)

        # Normalize attack labels to common categories
        label_map = {
            "benign": "Benign", "normal": "Benign", "0": "Benign",
            "dos": "DoS", "ddos": "DDoS", "probe": "Probe",
            "bruteforce": "Brute Force", "brute force": "Brute Force",
            "infiltration": "Infiltration", "bot": "Bot",
            "web attack": "Web Attack", "webattack": "Web Attack",
        }
        normalized = []
        for lbl in labels:
            low = str(lbl).lower().strip()
            normalized.append(label_map.get(low, str(lbl)))

        df["label"] = normalized

        if fit:
            self.label_encoder.fit(df["label"].unique().tolist())

        df["label_encoded"] = self.label_encoder.transform(df["label"])

        return df

    def _encode_categorical(self, df: pd.DataFrame) -> pd.DataFrame:
        """Encode categorical columns (drop or simple numeric mapping)."""
        df = df.copy()
        for col in self.categorical_columns:
            if col in df.columns and col not in ("label",):
                df[col] = pd.Categorical(df[col]).codes
        return df

    def fit_transform(
        self,
        df: pd.DataFrame,
        clip_outliers: bool = True,
        save_path: Optional[Path] = None
    ) -> pd.DataFrame:
        """Fit preprocessing and transform data."""
        self._identify_columns(df)
        df = self._handle_missing(df)
        df = self._handle_infinite(df)

        if clip_outliers:
            df = self._clip_outliers(df, lower=0.02, upper=0.98)

        df = self._encode_labels(df, fit=True)
        df = self._encode_categorical(df)

        # Scale numerical features
        if self.numerical_columns:
            valid_num = [c for c in self.numerical_columns if c in df.columns and c != "label_encoded"]
            if valid_num:
                df[valid_num] = self.scaler.fit_transform(df[valid_num])

        self._fitted = True

        if save_path:
            df.to_csv(save_path, index=False)

        return df

    def transform(
        self,
        df: pd.DataFrame,
        save_path: Optional[Path] = None
    ) -> pd.DataFrame:
        """Transform new data using fitted pipeline."""
        if not self._fitted:
            raise RuntimeError("Pipeline not fitted. Call fit_transform first.")

        self._handle_missing(df)
        self._handle_infinite(df)
        df = self._encode_labels(df, fit=False)
        df = self._encode_categorical(df)

        valid_num = [c for c in self.numerical_columns if c in df.columns and c != "label_encoded"]
        if valid_num:
            df[valid_num] = self.scaler.transform(df[valid_num])

        if save_path:
            df.to_csv(save_path, index=False)

        return df

    def get_feature_columns(self, df: pd.DataFrame) -> list:
        """Get list of feature columns (exclude label)."""
        exclude = {"label", "label_encoded"}
        return [c for c in df.columns if c not in exclude]
