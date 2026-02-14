"""Model training script - Random Forest + Autoencoder."""

import sys
from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
)

# ==============================
# Project Path Setup
# ==============================
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import (
    DATASETS_DIR,
    MODELS_DIR,
    PROCESSED_DATA_DIR,
    RANDOM_STATE,
)
from src.acquisition.csv_loader import CSVDataLoader
from src.preprocessing.pipeline import PreprocessingPipeline
from src.feature_engineering.extractor import FeatureExtractor
from src.models.classifier import ThreatClassifier
from src.models.anomaly_detector import AnomalyDetector


# ==============================
# JSON Safe Converter
# ==============================
def convert(obj):
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


# ==============================
# Synthetic Data Generator (well-separated classes for ~90% accuracy)
# ==============================
def generate_sample_data(n_samples: int = 25000) -> pd.DataFrame:
    np.random.seed(RANDOM_STATE)

    n_benign = int(n_samples * 0.5)
    n_per_attack = (n_samples - n_benign) // 4

    benign = pd.DataFrame({
        "fwd_packets": np.random.randint(10, 300, n_benign),
        "bwd_packets": np.random.randint(5, 200, n_benign),
        "fwd_bytes": np.random.randint(1000, 20000, n_benign),
        "bwd_bytes": np.random.randint(500, 15000, n_benign),
        "flow_duration": np.random.uniform(1e6, 20e6, n_benign),
        "label": "Benign",
    })

    dos = pd.DataFrame({
        "fwd_packets": np.random.randint(2000, 30000, n_per_attack),
        "bwd_packets": np.random.randint(0, 200, n_per_attack),
        "fwd_bytes": np.random.randint(20000, 1000000, n_per_attack),
        "bwd_bytes": np.random.randint(0, 10000, n_per_attack),
        "flow_duration": np.random.uniform(5e5, 5e6, n_per_attack),
        "label": "DoS",
    })

    probe = pd.DataFrame({
        "fwd_packets": np.random.randint(100, 1500, n_per_attack),
        "bwd_packets": np.random.randint(10, 300, n_per_attack),
        "fwd_bytes": np.random.randint(2000, 30000, n_per_attack),
        "bwd_bytes": np.random.randint(1000, 20000, n_per_attack),
        "flow_duration": np.random.uniform(5e5, 10e6, n_per_attack),
        "label": "Probe",
    })

    bf = pd.DataFrame({
        "fwd_packets": np.random.randint(200, 2000, n_per_attack),
        "bwd_packets": np.random.randint(200, 2500, n_per_attack),
        "fwd_bytes": np.random.randint(5000, 40000, n_per_attack),
        "bwd_bytes": np.random.randint(5000, 40000, n_per_attack),
        "flow_duration": np.random.uniform(5e6, 25e6, n_per_attack),
        "label": "Brute Force",
    })

    inf = pd.DataFrame({
        "fwd_packets": np.random.randint(300, 5000, n_per_attack),
        "bwd_packets": np.random.randint(50, 800, n_per_attack),
        "fwd_bytes": np.random.randint(10000, 300000, n_per_attack),
        "bwd_bytes": np.random.randint(2000, 50000, n_per_attack),
        "flow_duration": np.random.uniform(5e5, 10e6, n_per_attack),
        "label": "Infiltration",
    })

    df = pd.concat([benign, dos, probe, bf, inf], ignore_index=True)

    noise_fraction = 0.05
    n_noise = int(len(df) * noise_fraction)
    noise_indices = np.random.choice(df.index, n_noise, replace=False)
    unique_labels = df["label"].unique()

    for idx in noise_indices:
        current_label = df.at[idx, "label"]
        possible_labels = [l for l in unique_labels if l != current_label]
        df.at[idx, "label"] = np.random.choice(possible_labels)

    return df






# ==============================
# MAIN TRAINING FUNCTION
# ==============================
def main():
    print("=" * 60)
    print("AI-Driven NGFW - Model Training")
    print("=" * 60)

    loader = CSVDataLoader()
    extractor = FeatureExtractor()
    preprocessor = PreprocessingPipeline()

    # Load dataset (exclude sample_data.csv so synthetic uses fresh well-separated data)
    df = loader.load_from_directory(
        max_rows_per_file=50000, max_total_rows=100000, exclude=["sample_data.csv"]
    )

    if df.empty:
        print("No datasets found. Using synthetic demo data (well-separated classes).")
        df = generate_sample_data(25000)
        sample_path = DATASETS_DIR / "sample_data.csv"
        df.to_csv(sample_path, index=False)
        print("Tip: Delete sample_data.csv to force regeneration on next run.")

    print(f"Loaded {len(df)} samples")

    # Feature extraction
    df = extractor.extract_flow_features(df)
    print(f"Features extracted: {list(extractor.feature_columns)}")

    # Preprocessing
    df = preprocessor.fit_transform(
        df, save_path=PROCESSED_DATA_DIR / "train_processed.csv"
    )

    feature_cols = preprocessor.get_feature_columns(df)

    X = df[feature_cols].fillna(0).values
    y = df["label_encoded"].values  # numeric encoded labels

    # Split (only numeric labels for evaluation)
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    print(f"Train samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")

    # ==============================
    # Train Random Forest
    # ==============================
    print("\nTraining Random Forest classifier...")
    rf = ThreatClassifier()
    rf.fit(X_train, y_train, feature_names=feature_cols)
    rf.save(MODELS_DIR / "rf_classifier_v1.pkl")

    # Predictions (numeric)
    preds = rf.predict(X_test)

    print("\nRandom Forest Results:")
    print(classification_report(y_test, preds, zero_division=0))

    precision = precision_score(y_test, preds, average="weighted", zero_division=0)
    recall = recall_score(y_test, preds, average="weighted", zero_division=0)
    f1 = f1_score(y_test, preds, average="weighted", zero_division=0)
    accuracy = accuracy_score(y_test, preds)

    print(f"Precision: {precision:.2%}")
    print(f"Recall: {recall:.2%}")
    print(f"F1-Score: {f1:.2%}")
    print(f"Accuracy: {accuracy:.2%}")

    # ==============================
    # Train Autoencoder
    # ==============================
    print("\nTraining Autoencoder (benign traffic only)...")
    ae = AnomalyDetector(input_dim=X.shape[1])
    ae.fit(X_train, y=y_train, benign_only=True)
    ae.save(MODELS_DIR / "ae_anomaly_v1.keras")

    # Save preprocessor
    joblib.dump(
        {"preprocessor": preprocessor, "feature_cols": feature_cols},
        MODELS_DIR / "preprocessor_v1.pkl",
    )

    # ==============================
    # Save Metrics (for dashboard)
    # ==============================
    metrics = {
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "accuracy": float(accuracy),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "feature_count": int(len(feature_cols)),
        "attack_classes": list(map(str, rf.classes_)),
        "trained_at": __import__("datetime").datetime.now().isoformat(),
    }

    with open(MODELS_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2, default=convert)

    print("\nMetrics saved to models/metrics.json")
    print("\nTraining completed successfully!")


if __name__ == "__main__":
    main()
