"""Explainable AI for security decisions."""

from typing import Optional
import numpy as np
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


class ThreatExplainer:
    """Generate interpretable explanations for threat decisions."""

    def __init__(self, feature_importance: Optional[dict] = None):
        self.feature_importance = feature_importance or {}

    def from_classifier(self, classifier) -> "ThreatExplainer":
        """Extract feature importance from trained classifier."""
        self.feature_importance = classifier.get_feature_importance()
        return self

    def explain_prediction(
        self,
        feature_values: np.ndarray,
        feature_names: list,
        top_k: int = 5,
    ) -> dict:
        """Generate explanation for a single prediction.

        Weights global feature importance by how much each feature DEVIATES
        in this specific flow (scaled values far from 0 = more anomalous).
        This makes the explanation change with the input data.
        """
        if not feature_names or len(feature_values) == 0:
            return {"message": "Insufficient data for explanation"}

        base_imp = self.feature_importance or {}
        # Align names with values (values may be longer if padded)
        vals = np.asarray(feature_values).flatten()
        names = feature_names[: len(vals)] if len(feature_names) >= len(vals) else feature_names

        # Weight by deviation: |scaled_value| = how far from "normal" (0)
        # Higher deviation => feature contributed more to this specific decision
        data_dependent = {}
        for i, name in enumerate(names):
            if i >= len(vals):
                break
            base = base_imp.get(name, 0.1)
            deviation = 1.0 + min(abs(float(vals[i])), 5.0)  # cap extreme values
            data_dependent[name] = base * deviation

        sorted_items = sorted(data_dependent.items(), key=lambda x: x[1], reverse=True)[:top_k]
        total = sum(v for _, v in sorted_items) or 1e-6
        return {f: round(v / total, 2) for f, v in sorted_items}

    def explain_lateral_movement_example(self) -> dict:
        """Example from paper: lateral movement detection."""
        return {
            "abnormal_session_duration": 0.32,
            "access_to_sensitive_internal_assets": 0.27,
            "protocol_misuse": 0.21,
            "unusual_packet_rate": 0.12,
            "traffic_directionality": 0.08,
        }
