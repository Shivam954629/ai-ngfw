"""Application settings and configuration."""

import os
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
DATASETS_DIR = DATA_DIR / "datasets"
MODELS_DIR = PROJECT_ROOT / "models"
LOGS_DIR = PROJECT_ROOT / "logs"

# Create directories if they don't exist
for d in [RAW_DATA_DIR, PROCESSED_DATA_DIR, DATASETS_DIR, MODELS_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Database
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://user:pass@localhost:5432/ngfw"
)

# Model config (tuned for ~90% accuracy)
RF_ESTIMATORS = 200
RF_MAX_DEPTH = 25
AE_ENCODING_DIM = 32
AE_EPOCHS = 50
AE_BATCH_SIZE = 64
TRAIN_TEST_SPLIT = 0.2
RANDOM_STATE = 42

# Zero Trust thresholds
RISK_THRESHOLD_LOW = 0.3
RISK_THRESHOLD_MEDIUM = 0.6
RISK_THRESHOLD_HIGH = 0.8

# Policy actions
ACTION_ALLOW = "allow"
ACTION_ADAPTIVE_AUTH = "adaptive_auth"
ACTION_RESTRICT = "restrict"
ACTION_BLOCK = "block"
