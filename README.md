# 🛡️ AI-Driven Next-Generation Firewall (AI-NGFW)

> Dynamic Threat Detection & Zero Trust Implementation  
> Final Year Project — IIMT College of Engineering, 2025

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=black)
![ML](https://img.shields.io/badge/ML-RandomForest+Autoencoder-FF6F00?style=flat)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-Academic-red?style=flat)

---

## 📌 Overview

AI-NGFW is an intelligent network security system that uses **Machine Learning** to detect cyber threats in real-time. Unlike traditional firewalls, it uses a dual-model AI pipeline combined with a Zero Trust Policy Engine.

Based on **IJRIAS Research Paper** — *AI-Driven Next-Generation Firewall for Dynamic Threat Detection and Zero Trust Implementation*

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🤖 Dual AI Models | Random Forest (known attacks) + Autoencoder (zero-day anomalies) |
| 🔒 Zero Trust Engine | Dynamic risk-based access control with configurable thresholds |
| ⚡ Real-time Detection | 0.01ms average analysis latency |
| 🔍 Explainable AI | Risk factor breakdown for every decision |
| 📊 Live Dashboard | React-based UI with charts, alerts, demo mode |
| 📁 Export Reports | CSV/JSON export of all security alerts |
| 🐳 Docker Ready | One-command containerized deployment |

---

## 🖥️ Dashboard Preview

**🟢 Online | RF: ✓ | AE: ✓**

> Flow Analysis with DDoS Detection — Risk Score 60% | Action: Restrict | Latency: 0.01ms

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+

### 1️⃣ Clone & Setup
```bash
git clone https://github.com/Shivam954629/ai-ngfw.git
cd ai-ngfw
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

### 2️⃣ Train Models
```bash
python -m src.models.train
```

### 3️⃣ Start API Server — Terminal 1
```bash
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

### 4️⃣ Start Dashboard — Terminal 2
```bash
cd dashboard
npm install
npm run dev
```

### 5️⃣ Open Browser
```
Dashboard  →  http://localhost:3000
API Docs   →  http://localhost:8000/docs
```

---

## 🏗️ Project Structure
```
ai-ngfw/
├── config/                  # Settings & model config
├── data/                    # Datasets (gitignored)
├── models/                  # Trained model files
├── src/
│   ├── api/                 # FastAPI REST endpoints
│   ├── models/              # RF classifier + Autoencoder
│   ├── zero_trust/          # Zero Trust policy engine
│   ├── explainability/      # Explainable AI module
│   ├── preprocessing/       # Data pipeline
│   ├── feature_engineering/ # Feature extraction
│   └── acquisition/         # Traffic collection
├── dashboard/               # React frontend (Vite)
├── scripts/                 # Helper run scripts
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 🤖 AI Architecture
```
Network Traffic Input
        │
        ▼
Feature Extraction (12 features)
        │
        ├──► Random Forest ──► Known Attacks
        │                      (DoS, Brute Force, Probe)
        │
        └──► Autoencoder ───► Zero-Day Anomalies
                    │
                    ▼
        Zero Trust Policy Engine
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
        ALLOW    RESTRICT   BLOCK
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/analyze` | Analyze network flow for threats |
| `GET` | `/alerts` | Fetch security alerts |
| `GET` | `/stats` | Dashboard statistics |
| `GET` | `/model/metrics` | ML model performance metrics |
| `GET` | `/alerts/export` | Export alerts as CSV |
| `GET/POST` | `/policy` | Get/update Zero Trust thresholds |
| `GET` | `/health` | System health check |

📖 **Interactive API Docs:** `http://localhost:8000/docs`

---

## 🧪 Demo Attack Scenarios

| Preset | Settings | Expected Result |
|---|---|---|
| Normal | Packets: 100, Port: 443 | ✅ Benign — Allow |
| DDoS | Packets: 50,000, Duration: 2s | 🔴 DoS — Restrict |
| Brute Force | Packets: 5,000, Port: 22 | 🔴 Brute Force — Block |
| Suspicious | Packets: 1,000 | 🟡 Probe — Restrict |

---

## 🐳 Docker Deployment
```bash
docker-compose up --build
```

---

## 📄 Research Reference

Based on IJRIAS (International Journal of Research and Innovation in Applied Science) research paper on AI-Driven NGFW systems.

---

## 👨‍💻 About

**Developer:** Shivam  
**College:** IIMT College of Engineering  
**Year:** Final Year B.Tech (CSE) — 2025  
**License:** Academic/Research use only