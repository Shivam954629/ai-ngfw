"""Autoencoder-based anomaly detection for zero-day/unknown threats."""

import joblib
import numpy as np
from pathlib import Path
from typing import Optional, Tuple

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config.settings import AE_ENCODING_DIM, AE_EPOCHS, AE_BATCH_SIZE, MODELS_DIR

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    tf = keras = layers = None

# Fallback when TensorFlow not available
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class AnomalyDetector:
    """Autoencoder or IsolationForest for unsupervised anomaly detection."""

    def __init__(
        self,
        input_dim: int = 20,
        encoding_dim: int = AE_ENCODING_DIM,
        epochs: int = AE_EPOCHS,
        batch_size: int = AE_BATCH_SIZE,
    ):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.model: Optional[object] = None
        self.threshold: float = 0.0
        self._built = False
        self._use_sklearn = False  # Fallback to IsolationForest

    def _build_model(self):
        """Build symmetric encoder-decoder autoencoder or use IsolationForest."""
        if TF_AVAILABLE:
            input_layer = layers.Input(shape=(self.input_dim,))
            encoded = layers.Dense(64, activation="relu")(input_layer)
            encoded = layers.Dense(32, activation="relu")(encoded)
            encoded = layers.Dense(self.encoding_dim, activation="relu")(encoded)
            decoded = layers.Dense(32, activation="relu")(encoded)
            decoded = layers.Dense(64, activation="relu")(decoded)
            decoded = layers.Dense(self.input_dim, activation="linear")(decoded)
            self.model = keras.Model(input_layer, decoded)
            self.model.compile(
                optimizer=keras.optimizers.Adam(learning_rate=0.001),
                loss="mse",
            )
            self._use_sklearn = False
        elif SKLEARN_AVAILABLE:
            self.model = IsolationForest(contamination=0.05, random_state=42)
            self._use_sklearn = True
        else:
            raise RuntimeError("Install TensorFlow or scikit-learn for anomaly detection")
        self._built = True

    def fit(
        self,
        X: np.ndarray,
        benign_only: bool = True,
        y: Optional[np.ndarray] = None,
    ) -> "AnomalyDetector":
        """Train on normal/benign traffic only."""
        if benign_only and y is not None:
            benign_mask = np.array([str(l).lower() in ("benign", "normal", "0") for l in y])
            X = X[benign_mask]
        if len(X) == 0:
            X = y  # fallback

        self.input_dim = X.shape[1]
        self._build_model()

        if self._use_sklearn:
            self.model.fit(X)
            scores = -self.model.score_samples(X)  # higher = more anomalous
            self.threshold = float(np.percentile(scores, 95))
        else:
            self.model.fit(
                X, X,
                epochs=self.epochs,
                batch_size=self.batch_size,
                validation_split=0.1,
                verbose=0,
            )
            recon = self.model.predict(X, verbose=0)
            errors = np.mean(np.square(X - recon), axis=1)
            self.threshold = float(np.percentile(errors, 95))
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly score (higher = more anomalous)."""
        if not self._built or self.model is None:
            raise RuntimeError("Model not built. Call fit() first.")
        if self._use_sklearn:
            return -self.model.score_samples(X)
        recon = self.model.predict(X, verbose=0)
        return np.mean(np.square(X - recon), axis=1)

    def is_anomaly(self, X: np.ndarray, threshold: Optional[float] = None) -> np.ndarray:
        """Return boolean array: True if anomaly."""
        errors = self.predict(X)
        thresh = threshold if threshold is not None else self.threshold
        return errors > thresh

    def save(self, path: Optional[Path] = None) -> Path:
        """Save model and metadata."""
        path = path or (MODELS_DIR / "ae_anomaly_v1.keras")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if self._use_sklearn and self.model:
            joblib.dump(self.model, path.with_suffix(".pkl"))
        elif TF_AVAILABLE and self.model:
            self.model.save(str(path))
        meta_path = path.with_suffix(".npz")
        if path.suffix == ".pkl":
            meta_path = path.with_suffix(".npz")
        np.savez(meta_path, threshold=self.threshold, input_dim=self.input_dim, use_sklearn=self._use_sklearn)
        return path

    @classmethod
    def load(cls, path: Path) -> "AnomalyDetector":
        """Load model from disk."""
        path = Path(path)
        meta_path = path.with_suffix(".npz")
        if not meta_path.exists():
            meta_path = path.parent / (path.stem + ".npz")
        meta = np.load(meta_path)
        obj = cls(input_dim=int(meta["input_dim"]))
        use_sklearn = bool(meta.get("use_sklearn", False))
        if use_sklearn and SKLEARN_AVAILABLE:
            obj.model = joblib.load(path.with_suffix(".pkl"))
            obj._use_sklearn = True
        elif TF_AVAILABLE:
            obj.model = keras.models.load_model(str(path))
        else:
            raise RuntimeError("Cannot load model: TensorFlow not installed")
        obj.threshold = float(meta["threshold"])
        obj._built = True
        return obj
