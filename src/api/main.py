"""FastAPI application - AI-Driven NGFW API."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import os
import json
import joblib
import numpy as np
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from config.settings import MODELS_DIR
from src.zero_trust.policy_engine import ZeroTrustPolicyEngine, PolicyAction
from src.explainability.explainer import ThreatExplainer

# --- PostgreSQL setup ---
try:
    import psycopg2
    import psycopg2.extras
    DB_URL = os.environ.get("DATABASE_URL", "")
    _db_available = bool(DB_URL)
except ImportError:
    _db_available = False

def get_db():
    """Get DB connection."""
    if not _db_available:
        return None
    try:
        conn = psycopg2.connect(DB_URL, sslmode="require")
        return conn
    except Exception:
        return None

def init_db():
    """Create alerts table if not exists."""
    conn = get_db()
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id SERIAL PRIMARY KEY,
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    risk_score REAL,
                    threat_class TEXT,
                    action TEXT,
                    explanation TEXT
                )
            """)
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

def db_insert_alert(alert: dict):
    """Insert alert into DB."""
    conn = get_db()
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts (timestamp, src_ip, dst_ip, risk_score, threat_class, action, explanation)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                alert["timestamp"], alert["src_ip"], alert["dst_ip"],
                alert["risk_score"], alert["threat_class"], alert["action"],
                json.dumps(alert.get("explanation", {}))
            ))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

def db_get_alerts(limit: int = 50):
    """Get alerts from DB."""
    conn = get_db()
    if not conn:
        return None
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT %s", (limit,))
            rows = cur.fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return None
    finally:
        conn.close()

def db_delete_alert(timestamp: str, src_ip: str, dst_ip: str):
    """Delete specific alert from DB."""
    conn = get_db()
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM alerts WHERE timestamp=%s AND src_ip=%s AND dst_ip=%s",
                (timestamp, src_ip, dst_ip)
            )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

def db_delete_all_alerts():
    """Delete all alerts from DB."""
    conn = get_db()
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM alerts")
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

def db_get_stats():
    """Get stats from DB."""
    conn = get_db()
    if not conn:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM alerts")
            total = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM alerts WHERE risk_score >= 0.8")
            high = cur.fetchone()[0]
            cur.execute("SELECT threat_class, COUNT(*) FROM alerts GROUP BY threat_class")
            breakdown = {row[0]: row[1] for row in cur.fetchall()}
        return {"total_alerts": total, "high_risk_count": high, "threat_breakdown": breakdown}
    except Exception:
        return None
    finally:
        conn.close()


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


# --- Email Alert ---
def send_alert_email(alert: dict):
    """Send email notification for high-risk threats."""
    import smtplib
    from email.mime.text import MIMEText
    smtp_user  = os.environ.get("SMTP_USER", "")
    smtp_pass  = os.environ.get("SMTP_PASS", "")
    alert_to   = os.environ.get("ALERT_EMAIL", smtp_user)
    if not smtp_user or not smtp_pass:
        return
    try:
        subject = f"[NGFW ALERT] {alert['threat_class']} detected — {alert['action'].upper()}"
        body = (
            f"AI-Driven NGFW Security Alert\n"
            f"{'='*40}\n"
            f"Threat Class : {alert['threat_class']}\n"
            f"Risk Score   : {alert['risk_score']*100:.1f}%\n"
            f"Action       : {alert['action'].upper()}\n"
            f"Source IP    : {alert['src_ip']}\n"
            f"Dest IP      : {alert['dst_ip']}\n"
            f"Timestamp    : {alert['timestamp']}\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = smtp_user
        msg["To"]      = alert_to
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(smtp_user, smtp_pass)
            s.sendmail(smtp_user, alert_to, msg.as_string())
    except Exception as e:
        print(f"Email alert failed: {e}")


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
    init_db()
    yield


app = FastAPI(
    title="AI-Driven NGFW API",
    description="Dynamic Threat Detection and Zero Trust Implementation",
    version="1.0.0",
    lifespan=lifespan,
)

# --- Manual Rate Limiter (30 requests/minute per API key) ---
from collections import defaultdict
import time as _time

_rate_store: dict = defaultdict(list)
RATE_LIMIT = 30
RATE_WINDOW = 60  # seconds

def check_rate_limit(key: str) -> bool:
    """Returns True if allowed, False if rate limited."""
    now = _time.time()
    window_start = now - RATE_WINDOW
    _rate_store[key] = [t for t in _rate_store[key] if t > window_start]
    if len(_rate_store[key]) >= RATE_LIMIT:
        return False
    _rate_store[key].append(now)
    return True

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- API Key Authentication ---
API_KEY = os.environ.get("API_KEY", "")

@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    # Skip auth for health check, docs and CORS preflight
    if request.method == "OPTIONS":
        return await call_next(request)
    if request.url.path in ["/health", "/docs", "/openapi.json", "/redoc"]:
        return await call_next(request)
    # If no API_KEY set, skip auth
    if not API_KEY:
        return await call_next(request)
    # Check header
    key = request.headers.get("X-API-Key", "")
    if key != API_KEY:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid or missing API key"}
        )
    return await call_next(request)


def _flow_to_features(req: FlowRequest) -> np.ndarray:
    """Convert API request to feature vector matching training pipeline."""
    dur = max(req.duration, 0.001)
    pc = max(req.packet_count, 1)
    bv = max(req.byte_volume, 0)
    ratio = req.fwd_bwd_ratio or 1.0
    ratio = max(ratio, 0.1)
    fwd_pkts = int(pc * ratio / (1 + ratio))
    bwd_pkts = pc - fwd_pkts
    fwd_bytes = int(bv * ratio / (1 + ratio))
    bwd_bytes = bv - fwd_bytes
    packet_rate = pc / dur
    byte_rate = bv / dur
    pr_std = req.packet_rate_std or (packet_rate * 0.1)
    br_std = req.byte_rate_std or (byte_rate * 0.1)

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
    """Add risk based on obviously suspicious patterns."""
    dur = max(duration, 0.001)
    packet_rate = packet_count / dur
    byte_rate = byte_volume / dur
    h = 0.0
    if packet_rate > 5000:
        h += 0.25
    elif packet_rate > 1000:
        h += 0.12
    elif packet_rate > 300:
        h += 0.05
    if byte_rate > 2_000_000:
        h += 0.25
    elif byte_rate > 500_000:
        h += 0.12
    elif byte_rate > 100_000:
        h += 0.05
    if packet_count > 10000 and duration < 1.0:
        h += 0.15
    return min(h, 0.4)


@app.post("/analyze")
def analyze(request: Request, req: FlowRequest):
    """Analyze flow for threats and return risk + policy action."""

    # Rate limit check
    client_key = request.headers.get("X-API-Key", request.client.host if request.client else "unknown")
    if not check_rate_limit(client_key):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded: max 30 requests per minute"
        )
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
        ai_score = max(ai_score, 0.95)

    # ---------------- BRUTE FORCE HIGH VOLUME ----------------
    if req.dst_port == 22 and req.packet_count > 3000:
        threat_class = "Brute Force"
        ai_score = max(ai_score, 0.95)

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
        if req.packet_count > 3000:
            threat_class = "Brute Force"
            ai_score = max(ai_score, 0.95)
        elif req.packet_count > 800:
            threat_class = "Brute Force"
            ai_score = max(ai_score, 0.60)

    # HTTP/HTTPS flood pattern
    elif req.dst_port in [80, 443]:
        if req.packet_count > 15000:
            threat_class = "DoS"
            ai_score = max(ai_score, 0.95)
        elif req.packet_count > 5000:
            threat_class = "DoS"
            ai_score = max(ai_score, 0.80)

    # DB port suspicious access — Adaptive Auth range
    elif req.dst_port in [3306, 5432, 1433, 27017]:
        if req.packet_count > 1000:
            threat_class = "Probe"
            ai_score = max(ai_score, 0.75)
        elif req.packet_count > 100:
            threat_class = "Probe"
            ai_score = 0.35

    # ---------------- BENIGN MINIMUM FLOOR ----------------
    # Real networks always have baseline risk (misconfigs, recon, etc.)
    if threat_class == "Benign":
        ai_score = max(ai_score, 0.18)

    # ---------------- POLICY ENGINE ----------------
    assessment = policy_engine.evaluate(
        ai_threat_score=ai_score,
        threat_class=threat_class,
        dst_ip=req.dst_ip,
        dst_port=req.dst_port,
        anomaly_score=anomaly_score,
        explanation=expl if expl else None,
    )

    # Build meaningful flow-specific explanation
    dur = max(req.duration, 0.001)
    packet_rate = req.packet_count / dur
    byte_rate = req.byte_volume / dur
    ratio = req.fwd_bwd_ratio or 1.0

    # Each factor scored by how anomalous it is
    pr_score  = min(packet_rate / 1000, 1.0)
    br_score  = min(byte_rate / 500_000, 1.0)
    pc_score  = min(req.packet_count / 5000, 1.0)
    bv_score  = min(req.byte_volume / 1_000_000, 1.0)
    rat_score = min(abs(ratio - 1.0) / 5.0, 1.0)

    # Threat-specific meaningful weights
    if threat_class == "DoS":
        final_expl = {
            "packet_rate":   0.38,
            "byte_rate":     0.28,
            "packet_count":  0.18,
            "byte_volume":   0.12,
            "fwd_bwd_ratio": 0.04,
        }
    else:
        if threat_class == "Brute Force":
            pc_score  = min(pc_score * 2.0, 1.0)
            rat_score = min(rat_score * 2.0, 1.0)
        elif threat_class == "Probe":
            rat_score = min(rat_score * 1.5, 1.0)
            bv_score  = min(bv_score * 1.5, 1.0)

        total = pr_score + br_score + pc_score + bv_score + rat_score or 1.0
        final_expl = {
            "packet_rate":   round(pr_score  / total, 2),
            "byte_rate":     round(br_score  / total, 2),
            "packet_count":  round(pc_score  / total, 2),
            "byte_volume":   round(bv_score  / total, 2),
            "fwd_bwd_ratio": round(rat_score / total, 2),
        }

    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": req.src_ip,
        "dst_ip": req.dst_ip,
        "risk_score": round(assessment.risk_score, 4),
        "threat_class": threat_class,
        "action": assessment.action.value,
        "explanation": final_expl,
    }

    # ---------------- ALERT STORAGE ----------------
    if assessment.risk_score >= 0.3:
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
            db_insert_alert(alert)
            # Send email for high risk threats
            if assessment.risk_score >= 0.7:
                send_alert_email(alert)

        if len(alerts) > 100:
            alerts.pop(0)

    # ---------------- RESPONSE ----------------
    return {
        "risk_score": round(assessment.risk_score, 4),
        "threat_class": threat_class,
        "action": assessment.action.value,
        "explanation": final_expl,
        "policy_latency_ms": assessment.policy_latency_ms,
    }


@app.get("/alerts")
def get_alerts(limit: int = 50):
    """Fetch security alerts — DB first, fallback to memory."""
    db_alerts = db_get_alerts(limit)
    if db_alerts is not None:
        return {"alerts": db_alerts, "count": len(db_alerts)}
    return {"alerts": alerts[-limit:][::-1], "count": len(alerts)}


@app.get("/stats")
def get_stats():
    """Aggregate statistics — DB first, fallback to memory."""
    db_stats = db_get_stats()
    if db_stats is not None:
        return db_stats
    high_risk = sum(1 for a in alerts if (a.get("risk_score") or 0) >= 0.8)
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
    """Delete one alert or all alerts."""
    global alerts
    if timestamp and src_ip and dst_ip:
        alerts = [a for a in alerts if not (
            a.get("timestamp") == timestamp and
            a.get("src_ip") == src_ip and
            a.get("dst_ip") == dst_ip
        )]
        db_delete_alert(timestamp, src_ip, dst_ip)
    else:
        alerts.clear()
        db_delete_all_alerts()
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
