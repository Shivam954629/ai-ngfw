"""Random Forest classifier for known attack detection."""

import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from typing import Optional, Tuple

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config.settings import RF_ESTIMATORS, RF_MAX_DEPTH, RANDOM_STATE, MODELS_DIR


class ThreatClassifier:
    """Random Forest-based threat classifier for known attack categories."""

    def __init__(
        self,
        n_estimators: int = RF_ESTIMATORS,
        max_depth: int = RF_MAX_DEPTH,
        random_state: int = RANDOM_STATE,
    ):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,
            class_weight="balanced",
            min_samples_leaf=2,
            min_samples_split=5,
        )
        self.feature_names: list = []
        self.classes_: list = []

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        feature_names: Optional[list] = None,
    ) -> "ThreatClassifier":
        """Train the classifier."""
        self.feature_names = feature_names or [f"f{i}" for i in range(X.shape[1])]
        self.model.fit(X, y)
        self.classes_ = list(self.model.classes_)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict attack class."""
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities."""
        return self.model.predict_proba(X)

    def predict_with_confidence(
        self, X: np.ndarray, confidence_threshold: float = 0.7
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Return predictions and confidence scores.
        If max prob < threshold, mark as 'unknown' for anomaly detector.
        """
        proba = self.predict_proba(X)
        max_proba = np.max(proba, axis=1)
        preds = self.model.predict(X)

        # Low confidence -> defer to anomaly detector
        unknown_mask = max_proba < confidence_threshold
        if unknown_mask.any():
            preds = preds.astype(object)
            preds[unknown_mask] = "Unknown"

        return preds, max_proba

    def get_feature_importance(self) -> dict:
        """Get feature importance for explainability."""
        return dict(zip(
            self.feature_names,
            self.model.feature_importances_.tolist()
        ))

    def cross_validate(
        self,
        X: np.ndarray,
        y: np.ndarray,
        cv: int = 5,
    ) -> dict:
        """Perform cross-validation and return metrics."""
        scores = cross_val_score(self.model, X, y, cv=cv, scoring="f1_weighted")
        return {
            "f1_mean": float(scores.mean()),
            "f1_std": float(scores.std()),
            "scores": scores.tolist(),
        }

    def save(self, path: Optional[Path] = None) -> Path:
        """Save model to disk."""
        path = path or (MODELS_DIR / "rf_classifier_v1.pkl")
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "feature_names": self.feature_names,
                "classes_": self.classes_,
            },
            path,
        )
        return path

    @classmethod
    def load(cls, path: Path) -> "ThreatClassifier":
        """Load model from disk."""
        data = joblib.load(path)
        obj = cls()
        obj.model = data["model"]
        obj.feature_names = data.get("feature_names", [])
        obj.classes_ = data.get("classes_", [])
        return obj    