# AI-Driven NGFW — Final Year Project Guide

## Project Overview

**Title:** AI-Driven Next-Generation Firewall for Dynamic Threat Detection and Zero Trust Implementation  

**Institution:** IIMT College of Engineering, Greater Noida  
**Department:** Computer Science and Engineering  
**Reference Paper:** IJRIAS Volume X, Issue XII, December 2025

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AI-Driven NGFW System                         │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │   Dashboard  │  │  FastAPI     │  │  Zero Trust  │               │
│  │   (React)    │──│  REST API    │──│  Policy      │               │
│  │   :3000      │  │  :8000       │  │  Engine      │               │
│  └──────────────┘  └──────┬───────┘  └──────────────┘               │
│                           │                                          │
│  ┌────────────────────────┴────────────────────────┐                 │
│  │              Threat Detection Layer              │                 │
│  │  ┌─────────────────┐  ┌─────────────────────┐   │                 │
│  │  │ Random Forest   │  │ Autoencoder /       │   │                 │
│  │  │ (Known Attacks) │  │ IsolationForest     │   │                 │
│  │  │ DoS, Probe,     │  │ (Anomaly/Zero-day)  │   │                 │
│  │  │ Brute Force     │  │                     │   │                 │
│  │  └─────────────────┘  └─────────────────────┘   │                 │
│  └─────────────────────────────────────────────────┘                 │
│                           │                                          │
│  ┌────────────────────────┴────────────────────────┐                 │
│  │  Data: CIC-IDS2017/2018, UNSW-NB15, Synthetic   │                 │
│  └─────────────────────────────────────────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Key Features for Presentation

| Feature | Description |
|---------|-------------|
| **Flow Analysis** | Submit network flow (src/dst IP, ports, packets, bytes, duration) for real-time threat scoring |
| **Presets** | Normal, DDoS, Suspicious, Brute Force — quick demo scenarios |
| **Demo Mode** | Automatically runs all presets to showcase varying risk scores |
| **Risk Factors** | Data-dependent explanation showing which features contributed to the decision |
| **Statistics** | Total alerts, high-risk count, threat type breakdown |
| **Model Metrics** | Precision, Recall, F1, Accuracy from training |
| **Export** | Download alerts as CSV for reporting |
| **Config** | Adjust Zero Trust thresholds (Low, Medium, High) from UI |
| **About** | Project info, methodology, research reference |

---

## Demo Flow (Presentation Script)

1. **Start Services**
   - Terminal 1: `uvicorn src.api.main:app --reload --port 8000`
   - Terminal 2: `cd dashboard && npm run dev`

2. **Open Dashboard** — http://localhost:3000

3. **Show Normal Flow**
   - Click **Normal** preset → Analyze Flow → Green/low risk

4. **Show DDoS Detection**
   - Click **ddos** preset → Analyze Flow → Red/high risk

5. **Run Demo Mode**
   - Click **▶ Demo Mode** → Watch all presets analyzed sequentially

6. **Show Statistics**
   - Point to Statistics card (Total Alerts, High Risk, Threat Types)

7. **Show Model Metrics**
   - Point to Model Metrics (Precision, Recall, F1)

8. **Export & Config**
   - Export alerts as CSV
   - Open Config, adjust threshold, Save

---

## Methodology (For Viva)

- **Random Forest:** 100 trees, max depth 20; classifies known attacks (DoS, Probe, Brute Force, Infiltration)
- **Anomaly Detector:** IsolationForest (or Autoencoder if TensorFlow installed); detects zero-day/unknown threats
- **Zero Trust:** Risk score = 0.6×AI + 0.2×Asset + 0.2×Anomaly; actions: Allow, Adaptive Auth, Restrict, Block
- **Explainability:** Feature importance weighted by deviation from normal

---

## Comparison with Paper

| Metric | Paper (Proposed) | Our Implementation |
|--------|------------------|---------------------|
| Precision | ~91% | Depends on dataset/training |
| Recall | ~90% | Depends on dataset/training |
| F1-Score | ~90.5% | Displayed in dashboard |
| Policy Latency | <120ms | Typically <50ms |

---

## Tech Stack

- **Backend:** Python, FastAPI, scikit-learn, (TensorFlow optional)
- **Frontend:** React, Vite
- **Data:** CIC-IDS2017/2018, UNSW-NB15, or synthetic

---

## Future Enhancements

- Real-time packet capture integration
- Online/continual learning
- Multi-cloud deployment
- Advanced explainability (SHAP)
