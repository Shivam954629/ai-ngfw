"""Feature extraction for flow-level traffic analysis."""

import numpy as np
import pandas as pd
from typing import Optional
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


class FeatureExtractor:
    """Extract flow-level features for threat detection.

    Features from paper:
    - packet_count, byte_volume, session_duration
    - inter_arrival_time (mean, std, min, max)
    - protocol distribution, packet_rate, byte_rate
    - flow_direction (forward/backward ratio)
    - packet_rate_variance
    """

    # Standard feature names expected by models
    REQUIRED_FEATURES = [
        "packet_count", "byte_volume", "duration",
        "packet_rate", "byte_rate", "fwd_bwd_ratio",
        "packet_rate_std", "byte_rate_std",
    ]

    # Common dataset column mappings
    COLUMN_ALIASES = {
        "flow_duration": "duration",
        "tot_fwd_pkts": "fwd_packets",
        "tot_bwd_pkts": "bwd_packets",
        "tot_fwd_bytes": "fwd_bytes",
        "tot_bwd_bytes": "bwd_bytes",
        "fwd_psh_flags": "fwd_psh",
        "bwd_psh_flags": "bwd_psh",
    }

    def __init__(self):
        self.feature_columns: list = []

    def _normalize_column_names(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize column names across datasets."""
        df = df.copy()
        for old, new in self.COLUMN_ALIASES.items():
            if old in df.columns and new not in df.columns:
                df = df.rename(columns={old: new})
        return df

    def extract_flow_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract flow-level features from raw dataset."""
        df = self._normalize_column_names(df)

        result = pd.DataFrame()

        # Packet and byte totals
        if "fwd_packets" in df.columns and "bwd_packets" in df.columns:
            result["packet_count"] = df["fwd_packets"].fillna(0) + df["bwd_packets"].fillna(0)
        elif "packet_count" in df.columns:
            result["packet_count"] = df["packet_count"]
        else:
            result["packet_count"] = 1

        if "fwd_bytes" in df.columns and "bwd_bytes" in df.columns:
            result["byte_volume"] = df["fwd_bytes"].fillna(0) + df["bwd_bytes"].fillna(0)
        elif "byte_volume" in df.columns or "byte_volume" in [c.lower() for c in df.columns]:
            result["byte_volume"] = df.get("byte_volume", df.get("byte_volume", 0))
        else:
            result["byte_volume"] = 0

        # Duration
        dur_col = next((c for c in ["flow_duration", "duration", "dur"] if c in df.columns), None)
        if dur_col:
            result["duration"] = pd.to_numeric(df[dur_col], errors="coerce").fillna(0) / 1e6  # us to sec
        else:
            result["duration"] = 0.001  # default 1ms

        result["duration"] = result["duration"].replace(0, 0.001)

        # Derived: packet_rate, byte_rate
        result["packet_rate"] = result["packet_count"] / result["duration"]
        result["byte_rate"] = result["byte_volume"] / result["duration"]

        # Forward/backward ratio
        if "fwd_packets" in df.columns and "bwd_packets" in df.columns:
            fwd = df["fwd_packets"].fillna(0) + 1
            bwd = df["bwd_packets"].fillna(0) + 1
            result["fwd_bwd_ratio"] = fwd / bwd
        else:
            result["fwd_bwd_ratio"] = 1.0

        # Placeholder variance (dataset may have these)
        if "packet_rate_std" in df.columns:
            result["packet_rate_std"] = df["packet_rate_std"]
        else:
            result["packet_rate_std"] = result["packet_rate"] * 0.1

        if "byte_rate_std" in df.columns:
            result["byte_rate_std"] = df["byte_rate_std"]
        else:
            result["byte_rate_std"] = result["byte_rate"] * 0.1

        # Add other numeric columns that might be useful
        exclude = {"label", "label_encoded", "attack_cat"}
        for col in df.select_dtypes(include=[np.number]).columns:
            if col not in result.columns and col not in exclude:
                result[col] = df[col]

        if "label" in df.columns:
            result["label"] = df["label"]

        self.feature_columns = [c for c in result.columns if c != "label"]

        return result

    def extract_from_flow_dict(self, flow: dict) -> np.ndarray:
        """Extract feature vector from single flow dict (e.g., from API)."""
        pc = flow.get("packet_count", 1)
        bv = flow.get("byte_volume", 0)
        dur = max(flow.get("duration", 0.001), 0.001)

        features = {
            "packet_count": pc,
            "byte_volume": bv,
            "duration": dur,
            "packet_rate": pc / dur,
            "byte_rate": bv / dur,
            "fwd_bwd_ratio": flow.get("fwd_bwd_ratio", 1.0),
            "packet_rate_std": flow.get("packet_rate_std", pc / dur * 0.1),
            "byte_rate_std": flow.get("byte_rate_std", bv / dur * 0.1),
        }
        return np.array([features.get(f, 0) for f in self.REQUIRED_FEATURES])
