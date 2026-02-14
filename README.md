# AI-Driven Next-Generation Firewall (NGFW)

**Dynamic Threat Detection and Zero Trust Implementation**

Based on IJRIAS research paper - AI-Driven Next-Generation Firewall for Dynamic Threat Detection and Zero Trust Implementation.

## Features

- **AI-Based Threat Detection**: Random Forest (known attacks) + Autoencoder/IsolationForest (anomaly/zero-day)
- **Zero Trust Policy Engine**: Dynamic risk-based access control with configurable thresholds
- **Explainable Decisions**: Data-dependent risk factor breakdown
- **Flow-Level Analysis**: Packet count, byte volume, session duration, protocol behavior
- **REST API**: FastAPI endpoints for analysis, stats, export, policy
- **Dashboard**: Statistics, model metrics, export CSV, config panel, demo mode
- **Presentation Ready**: PROJECT_GUIDE.md for demo script and viva

## Quick Start

```bash
# 1. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate   # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Train models (uses synthetic data if no datasets)
python -m src.models.train

# 4. Run API server (Terminal 1)
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

# 5. Run dashboard (Terminal 2)
cd dashboard && npm install && npm run dev
```

**Dashboard:** http://localhost:3000 — Flow Analysis, Statistics, Model Metrics, Alerts with Export CSV, Config, Demo Mode, About.

See **PROJECT_GUIDE.md** for presentation script and viva preparation.

## Project Structure

```
ai-ngfw/
├── config/           # Settings and model config
├── data/             # Raw, processed, datasets
├── models/           # Saved trained models
├── src/
│   ├── acquisition/  # Traffic collection
│   ├── preprocessing/
│   ├── feature_engineering/
│   ├── models/       # RF + Autoencoder
│   ├── zero_trust/   # Policy engine
│   ├── api/          # FastAPI
│   └── explainability/
├── dashboard/        # React frontend
└── deployment/       # Docker configs
```

## License

Academic/Research use - IIMT College of Engineering
