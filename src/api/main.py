"""FastAPI application - AI-Driven NGFW API."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from config.settings import MODELS_DIR
from src.zero_trust.policy_engine import ZeroTrustPolicyEngine, PolicyAction
from src.explainability.explainer import ThreatExplainer


# -------------------------------
# Threat Class Label Mapping
# -------------------------------
CLASS_LABELS = {
    0: "Benign",
    1: "DoS",
    2: "Probe",
    3: "Brute Force",
    4: "Infiltration"
}



# --- Models ---
class FlowRequest(BaseModel):
    """Flow data for threat analysis."""
    src_ip: str = "192.168.1.10"
    dst_ip: str = "10.0.0.5"
    src_port: int = 12345
    dst_port: int = 80
    protocol: str = "TCP"
    packet_count: int = 100
    byte_volume: int = 10000
    duration: float = 5.2
    fwd_bwd_ratio: Optional[float] = 1.0
    packet_rate_std: Optional[float] = None
    byte_rate_std: Optional[float] = None


class PolicyUpdate(BaseModel):
    """Zero Trust policy update."""
    low_threshold: Optional[float] = None
    medium_threshold: Optional[float] = None
    high_threshold: Optional[float] = None


# --- Global state ---
rf_model = None
ae_model = None
preprocessor_data = None
policy_engine = ZeroTrustPolicyEngine()
explainer = ThreatExplainer()
alerts: list = []


def load_models():
    """Load trained models."""
    global rf_model, ae_model, preprocessor_data, explainer
    try:
        from src.models.classifier import ThreatClassifier
        rf_path = MODELS_DIR / "rf_classifier_v1.pkl"
        if rf_path.exists():
            rf_model = ThreatClassifier.load(rf_path)
            explainer.from_classifier(rf_model)
    except Exception as e:
        print(f"RF load warning: {e}")

    try:
        from src.models.anomaly_detector import AnomalyDetector
        ae_path = MODELS_DIR / "ae_anomaly_v1.keras"
        ae_pkl = MODELS_DIR / "ae_anomaly_v1.pkl"
        if ae_path.exists():
            ae_model = AnomalyDetector.load(ae_path)
        elif ae_pkl.exists():
            ae_model = AnomalyDetector.load(ae_pkl)
    except Exception as e:
        print(f"AE load warning: {e}")

    try:
        prep_path = MODELS_DIR / "preprocessor_v1.pkl"
        if prep_path.exists():
            preprocessor_data = joblib.load(prep_path)
    except Exception as e:
        print(f"Preprocessor load warning: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_models()
    yield
    # cleanup if needed


app = FastAPI(
    title="AI-Driven NGFW API",
    description="Dynamic Threat Detection and Zero Trust Implementation",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _flow_to_features(req: FlowRequest) -> np.ndarray:
    """Convert API request to feature vector matching training pipeline."""
    dur = max(req.duration, 0.001)
    pc = max(req.packet_count, 1)
    bv = max(req.byte_volume, 0)
    ratio = req.fwd_bwd_ratio or 1.0
    ratio = max(ratio, 0.1)
    # Derive fwd/bwd from ratio: fwd = pc * ratio/(1+ratio), bwd = pc/(1+ratio)
    fwd_pkts = int(pc * ratio / (1 + ratio))
    bwd_pkts = pc - fwd_pkts
    fwd_bytes = int(bv * ratio / (1 + ratio))
    bwd_bytes = bv - fwd_bytes
    packet_rate = pc / dur
    byte_rate = bv / dur
    pr_std = req.packet_rate_std or (packet_rate * 0.1)
    br_std = req.byte_rate_std or (byte_rate * 0.1)

    # Build feature dict matching extract_flow_features order
    feat_dict = {
        "packet_count": pc, "byte_volume": bv, "duration": dur,
        "packet_rate": packet_rate, "byte_rate": byte_rate,
        "fwd_bwd_ratio": ratio,
        "packet_rate_std": pr_std, "byte_rate_std": br_std,
        "fwd_packets": fwd_pkts, "bwd_packets": bwd_pkts,
        "fwd_bytes": fwd_bytes, "bwd_bytes": bwd_bytes,
    }

    fc = preprocessor_data.get("feature_cols", []) if preprocessor_data else []
    if fc:
        features = np.array([[feat_dict.get(c, 0) for c in fc]], dtype=np.float64)
        prep = preprocessor_data.get("preprocessor")
        if prep and hasattr(prep, "scaler"):
            features = prep.scaler.transform(features)
    else:
        features = np.array([[
            pc, bv, dur, packet_rate, byte_rate, ratio, pr_std, br_std,
            fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes
        ]], dtype=np.float64)
    return features


@app.get("/health")
def health():
    """Health check."""
    return {
        "status": "ok",
        "models_loaded": {
            "random_forest": rf_model is not None,
            "autoencoder": ae_model is not None,
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


def _heuristic_risk(packet_count: int, byte_volume: int, duration: float) -> float:
    """Add risk based on obviously suspicious patterns (high volume, burst)."""
    dur = max(duration, 0.001)
    packet_rate = packet_count / dur
    byte_rate = byte_volume / dur
    h = 0.0
    if packet_rate > 1000:
        h += 0.3
    elif packet_rate > 500:
        h += 0.15
    if byte_rate > 1_000_000:
        h += 0.3
    elif byte_rate > 100_000:
        h += 0.15
    if packet_count > 5000 and duration < 1.0:
        h += 0.2
    return min(h, 0.5)


@app.post("/analyze")
def analyze(req: FlowRequest):
    """Analyze flow for threats and return risk + policy action."""

    # ---------------- INPUT VALIDATION ----------------
    if req.packet_count <= 0 or req.duration <= 0:
        raise HTTPException(
            status_code=400,
            detail="Invalid flow: packet_count and duration must be > 0"
        )

    features = _flow_to_features(req)

    ai_score = 0.0
    threat_class = "Benign"
    expl = {}
    anomaly_score = 0.0

    # ---------------- RF CLASSIFIER ----------------
    if rf_model:
        preds, conf = rf_model.predict_with_confidence(
            features, confidence_threshold=0.65
        )

        pred = preds[0]
        conf_val = float(conf[0])

        if isinstance(pred, (int, np.integer)):
            threat_class = CLASS_LABELS.get(int(pred), "Benign")
        else:
            threat_class = str(pred)

        if threat_class not in CLASS_LABELS.values():
            threat_class = "Benign"

        if threat_class != "Benign":
            ai_score = 0.6 + 0.3 * conf_val
        else:
            ai_score = 0.05 * (1.0 - conf_val)

        expl = explainer.explain_prediction(
            features[0],
            rf_model.feature_names if hasattr(rf_model, "feature_names") else [],
            top_k=5,
        )

    # ---------------- EXTREME VOLUMETRIC DOS ----------------
    packet_rate = req.packet_count / max(req.duration, 0.001)

    if packet_rate > 10000 and req.packet_count > 20000:
        threat_class = "DoS"
        ai_score = max(ai_score, 0.9)

    # ---------------- AUTOENCODER ----------------
    if ae_model and threat_class == "Benign" and ai_score < 0.15:
        try:
            n = min(features.shape[1], ae_model.input_dim)
            err = ae_model.predict(features[:, :n])
            raw_err = float(err[0])
            thresh = ae_model.threshold or 1.0

            anomaly_score = raw_err / max(thresh, 1e-6)

            if anomaly_score > 1.5:
                threat_class = "Anomaly"
                ai_score = min(0.5 + 0.3 * min(anomaly_score, 2.0), 0.85)

        except Exception:
            pass

    # ---------------- HEURISTIC BOOST ----------------
    heuristic = _heuristic_risk(
        req.packet_count,
        req.byte_volume,
        req.duration
    )
    ai_score = min(ai_score + heuristic, 1.0)

    # ---------------- PORT-SENSITIVE BOOST ----------------

    # SSH brute-force pattern
    if req.dst_port == 22:
        if req.packet_count > 5000:
            threat_class = "Brute Force"
            ai_score = max(ai_score, 0.85)
        elif req.packet_count > 1500:
            threat_class = "Brute Force"
            ai_score = max(ai_score, 0.75)

    # HTTP/HTTPS flood pattern
    elif req.dst_port in [80, 443]:
        if req.packet_count > 8000:
            threat_class = "DoS"
            ai_score = max(ai_score, 0.85)
        elif req.packet_count > 5000:
            threat_class = "DoS"
            ai_score = max(ai_score, 0.75)

    # ---------------- POLICY ENGINE ----------------
    assessment = policy_engine.evaluate(
        ai_threat_score=ai_score,
        threat_class=threat_class,
        dst_ip=req.dst_ip,
        dst_port=req.dst_port,
        anomaly_score=anomaly_score,
        explanation=expl if expl else None,
    )

    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": req.src_ip,
        "dst_ip": req.dst_ip,
        "risk_score": round(assessment.risk_score, 4),
        "threat_class": threat_class,
        "action": assessment.action.value,
        "explanation": assessment.explanation,
    }

    # ---------------- ALERT STORAGE ----------------
    if assessment.risk_score >= 0.4:
        if not any(
            a["src_ip"] == alert["src_ip"]
            and a["dst_ip"] == alert["dst_ip"]
            and a["threat_class"] == alert["threat_class"]
            and abs(
                datetime.fromisoformat(a["timestamp"]) -
                datetime.fromisoformat(alert["timestamp"])
            ).total_seconds() < 30
            for a in alerts
        ):
            alerts.append(alert)

        if len(alerts) > 100:
            alerts.pop(0)

    # ---------------- RESPONSE ----------------
    return {
        "risk_score": round(assessment.risk_score, 4),
        "threat_class": threat_class,
        "action": assessment.action.value,
        "explanation": assessment.explanation,
        "policy_latency_ms": assessment.policy_latency_ms,
    }



@app.get("/alerts")
def get_alerts(limit: int = 50):
    """Fetch security alerts."""
    return {"alerts": alerts[-limit:][::-1], "count": len(alerts)}




@app.get("/stats")
def get_stats():
    """Aggregate statistics for dashboard."""

    high_risk = sum(
        1 for a in alerts if (a.get("risk_score") or 0) >= 0.8
    )

    threat_counts = {}
    for a in alerts:
        t = a.get("threat_class")
        if not t:
            continue
        threat_counts[t] = threat_counts.get(t, 0) + 1

    return {
        "total_alerts": len(alerts),
        "high_risk_count": high_risk,
        "threat_breakdown": threat_counts,
    }



@app.get("/model/metrics")
def get_model_metrics():
    """Training metrics if available."""
    import json
    path = MODELS_DIR / "metrics.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {"message": "Run training to generate metrics"}


@app.get("/alerts/export")
def export_alerts(format: str = "json"):
    """Export alerts as JSON or CSV."""
    if format == "csv":
        import csv
        from io import StringIO
        output = StringIO()
        if alerts:
            writer = csv.DictWriter(output, fieldnames=["timestamp", "src_ip", "dst_ip", "risk_score", "threat_class", "action"])
            writer.writeheader()
            for a in alerts[-100:][::-1]:
                writer.writerow({k: a.get(k) for k in ["timestamp", "src_ip", "dst_ip", "risk_score", "threat_class", "action"]})
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=alerts.csv"})
    return {"alerts": alerts[-100:][::-1]}


@app.delete("/alerts")
def delete_alerts(timestamp: Optional[str] = None, src_ip: Optional[str] = None, dst_ip: Optional[str] = None):
    """Delete one alert (by timestamp+src_ip+dst_ip) or all alerts if no params."""
    global alerts
    if timestamp and src_ip and dst_ip:
        alerts = [a for a in alerts if not (a.get("timestamp") == timestamp and a.get("src_ip") == src_ip and a.get("dst_ip") == dst_ip)]
    else:
        alerts.clear()
    return {"alerts": alerts[-50:][::-1], "count": len(alerts)}


@app.get("/policy")
def get_policy():
    """Get current Zero Trust policy thresholds."""
    return {
        "low_threshold": policy_engine.low_threshold,
        "medium_threshold": policy_engine.medium_threshold,
        "high_threshold": policy_engine.high_threshold,
    }


@app.post("/policy")
def update_policy(p: PolicyUpdate):
    """Update Zero Trust policy thresholds."""
    if p.low_threshold is not None:
        policy_engine.low_threshold = p.low_threshold
    if p.medium_threshold is not None:
        policy_engine.medium_threshold = p.medium_threshold
    if p.high_threshold is not None:
        policy_engine.high_threshold = p.high_threshold
    return get_policy()


@app.post("/model/retrain")
def retrain_model():
    """Trigger model retraining (admin)."""
    raise HTTPException(
        status_code=501,
        detail="Retraining endpoint - run: python -m src.models.train",
    )     