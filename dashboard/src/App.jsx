import { useState, useEffect, useCallback } from "react";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_URL || "https://ai-ngfw.onrender.com";

const PRESETS = {
  benign: {
    src_ip: "192.168.1.10",
    dst_ip: "8.8.8.8",
    src_port: 54321,
    dst_port: 443,
    protocol: "TCP",
    packet_count: 80,
    byte_volume: 12000,
    duration: 5.0,
    fwd_bwd_ratio: 1.2,
  },
  dos: {
    src_ip: "10.0.0.1",
    dst_ip: "192.168.1.1",
    src_port: 12345,
    dst_port: 80,
    protocol: "TCP",
    packet_count: 50000,
    byte_volume: 5000000,
    duration: 2.0,
    fwd_bwd_ratio: 10.0,
  },
  probe: {
    src_ip: "192.168.1.50",
    dst_ip: "10.0.0.100",
    src_port: 33333,
    dst_port: 3306,
    protocol: "TCP",
    packet_count: 200,
    byte_volume: 5000,
    duration: 3.0,
    fwd_bwd_ratio: 1.5,
  },
  bruteforce: {
    src_ip: "203.0.113.1",
    dst_ip: "192.168.1.10",
    src_port: 49152,
    dst_port: 22,
    protocol: "TCP",
    packet_count: 1500,
    byte_volume: 37500,
    duration: 8.0,
    fwd_bwd_ratio: 1.5,
  },
};

const emptyForm = {
  src_ip: "",
  dst_ip: "",
  src_port: "",
  dst_port: "",
  protocol: "TCP",
  packet_count: "",
  byte_volume: "",
  duration: "",
  fwd_bwd_ratio: "",
};
const defaultForm = {
  src_ip: "192.168.1.10",
  dst_ip: "8.8.8.8",
  src_port: 54321,
  dst_port: 443,
  protocol: "TCP",
  packet_count: 100,
  byte_volume: 10000,
  duration: 5.2,
  fwd_bwd_ratio: 1.0,
};

// ── Helper: risk color ────────────────────────────────
const getRiskColor = (score) => {
  if (score == null) return "#888";
  if (score < 0.4) return "#22c55e";
  if (score < 0.7) return "#f59e0b";
  return "#ef4444";
};

const getRiskLabel = (score) => {
  if (score == null) return "UNKNOWN";
  if (score < 0.4) return "LOW";
  if (score < 0.7) return "MEDIUM";
  return "HIGH";
};

// ── Timeline Chart (pure SVG, no extra library needed) ─
function TimelineChart({ history }) {
  if (!history || history.length < 2) {
    return (
      <div
        style={{
          textAlign: "center",
          color: "#555",
          padding: "1.5rem",
          fontSize: "0.82rem",
        }}
      >
        Run 2 or more analyses to see the risk timeline
      </div>
    );
  }
  const W = 520,
    H = 120,
    PL = 36,
    PR = 12,
    PT = 14,
    PB = 34;
  const chartW = W - PL - PR;
  const chartH = H - PT - PB;
  const ordered = [...history].reverse();
  const scores = ordered.map((h) => h.risk_score || 0);

  const points = scores.map((s, i) => {
    const x =
      PL +
      (scores.length === 1 ? chartW / 2 : (i / (scores.length - 1)) * chartW);
    const y = PT + chartH - s * chartH;
    return [x, y];
  });

  const polylineStr = points.map(([x, y]) => `${x},${y}`).join(" ");

  // Area fill path
  const areaPath = [
    `M ${points[0][0]},${PT + chartH}`,
    ...points.map(([x, y]) => `L ${x},${y}`),
    `L ${points[points.length - 1][0]},${PT + chartH}`,
    "Z",
  ].join(" ");

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ display: "block" }}>
      <defs>
        <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.25" />
          <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {/* Grid */}
      {[0, 0.5, 1].map((v) => {
        const y = PT + chartH - v * chartH;
        return (
          <g key={v}>
            <line
              x1={PL}
              y1={y}
              x2={W - PR}
              y2={y}
              stroke="#2a2a2a"
              strokeWidth="0.8"
              strokeDasharray="4,4"
            />
            <text
              x={PL - 4}
              y={y + 4}
              fontSize="9"
              fill="#555"
              textAnchor="end"
            >
              {(v * 100).toFixed(0)}%
            </text>
          </g>
        );
      })}
      {/* Danger zone */}
      <rect
        x={PL}
        y={PT}
        width={chartW}
        height={chartH * 0.3}
        fill="#ef4444"
        fillOpacity="0.04"
      />
      {/* Area */}
      <path d={areaPath} fill="url(#areaGrad)" />
      {/* Line */}
      <polyline
        points={polylineStr}
        fill="none"
        stroke="#3b82f6"
        strokeWidth="2"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      {/* Dots + labels */}
      {points.map(([x, y], i) => {
        const s = scores[i];
        const c = getRiskColor(s);
        return (
          <g key={i}>
            <circle
              cx={x}
              cy={y}
              r="5"
              fill={c}
              stroke="#111"
              strokeWidth="1.5"
            />
            <text
              x={x}
              y={y - 8}
              fontSize="8"
              fill={c}
              textAnchor="middle"
              fontWeight="600"
            >
              {(s * 100).toFixed(0)}%
            </text>
          </g>
        );
      })}
      {/* X axis labels */}
      {ordered.map((h, i) => {
        const x =
          PL +
          (scores.length === 1
            ? chartW / 2
            : (i / (scores.length - 1)) * chartW);
        const labelMap = { "Brute Force": "B.Force", Infiltration: "Infiltr." };
        const raw = h.threat_class || `#${i + 1}`;
        const label = labelMap[raw] || raw;
        return (
          <text
            key={i}
            x={x}
            y={H - 4}
            fontSize="6"
            fill="#555"
            textAnchor="middle"
          >
            {label}
          </text>
        );
      })}
    </svg>
  );
}

// ── History Table ─────────────────────────────────────
function HistoryTable({ history }) {
  if (!history || history.length === 0) return null;
  return (
    <div className="history-table-wrap">
      <table className="history-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Source IP</th>
            <th>Dest IP</th>
            <th>Threat</th>
            <th>Risk</th>
            <th>Action</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody>
          {history.map((h, i) => {
            const color = getRiskColor(h.risk_score);
            return (
              <tr key={i}>
                <td style={{ color: "#555" }}>{history.length - i}</td>
                <td>{h.input?.src_ip || "—"}</td>
                <td>{h.input?.dst_ip || "—"}</td>
                <td>
                  <span
                    className="threat-badge"
                    style={{ color, borderColor: color }}
                  >
                    {h.threat_class || "Benign"}
                  </span>
                </td>
                <td style={{ color, fontWeight: 600 }}>
                  {((h.risk_score || 0) * 100).toFixed(1)}%
                </td>
                <td>{h.action || "—"}</td>
                <td style={{ color: "#555" }}>
                  {h.policy_latency_ms ?? "—"} ms
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────
function App() {
  const [history, setHistory] = useState([]);
  const [health, setHealth] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [policy, setPolicy] = useState(null);
  const [flowForm, setFlowForm] = useState(defaultForm);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showAbout, setShowAbout] = useState(false);
  const [showConfig, setShowConfig] = useState(false);
  const [configTemp, setConfigTemp] = useState({
    low: 0.3,
    medium: 0.6,
    high: 0.8,
  });
  const [demoRunning, setDemoRunning] = useState(false);

  const fetchHealth = useCallback(async () => {
    try {
      setHealth(await (await fetch(`${API_BASE}/health`)).json());
    } catch {
      setHealth({ status: "error" });
    }
  }, []);

  const fetchAlerts = useCallback(async () => {
    try {
      const d = await (await fetch(`${API_BASE}/alerts?limit=50`)).json();
      const list = (d.alerts || []).filter(
        (v, i, arr) =>
          i ===
          arr.findIndex(
            (x) =>
              x.timestamp === v.timestamp &&
              x.src_ip === v.src_ip &&
              x.dst_ip === v.dst_ip,
          ),
      );
      setAlerts(list);
    } catch {
      setAlerts([]);
    }
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      setStats(await (await fetch(`${API_BASE}/stats`)).json());
    } catch {
      setStats(null);
    }
  }, []);

  const fetchMetrics = useCallback(async () => {
    try {
      setMetrics(await (await fetch(`${API_BASE}/model/metrics`)).json());
    } catch {
      setMetrics(null);
    }
  }, []);

  const fetchPolicy = useCallback(async () => {
    try {
      setPolicy(await (await fetch(`${API_BASE}/policy`)).json());
    } catch {
      setPolicy(null);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    fetchAlerts();
    fetchStats();
    fetchMetrics();
    fetchPolicy();
    const id = setInterval(() => {
      fetchHealth();
      fetchAlerts();
      fetchStats();
    }, 5000);
    return () => clearInterval(id);
  }, [fetchHealth, fetchAlerts, fetchStats, fetchMetrics, fetchPolicy]);

  const applyPreset = (key) => {
    setFlowForm(PRESETS[key] || defaultForm);
    setAnalysis(null);
    setError(null);
  };

  const analyze = async () => {
    setLoading(true);
    setAnalysis(null);
    setError(null);
    try {
      const payload = {
        ...flowForm,
        src_port: flowForm.src_port === "" ? 0 : Number(flowForm.src_port) || 0,
        dst_port: flowForm.dst_port === "" ? 0 : Number(flowForm.dst_port) || 0,
        packet_count:
          flowForm.packet_count === "" ? 0 : Number(flowForm.packet_count) || 0,
        byte_volume:
          flowForm.byte_volume === "" ? 0 : Number(flowForm.byte_volume) || 0,
        duration: flowForm.duration === "" ? 0 : Number(flowForm.duration) || 0,
        fwd_bwd_ratio:
          flowForm.fwd_bwd_ratio === ""
            ? 1
            : Number(flowForm.fwd_bwd_ratio) || 1,
      };
      const res = await fetch(`${API_BASE}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setAnalysis(data);
      setHistory((h) => [
        { ...data, input: { ...flowForm } },
        ...h.slice(0, 19),
      ]);
      fetchAlerts();
      fetchStats();
    } catch (e) {
      setError(e.message || "Failed to analyze — Is the API running?");
      setAnalysis(null);
    } finally {
      setLoading(false);
    }
  };

  const deleteAlert = async (a) => {
    try {
      const p = new URLSearchParams({
        timestamp: a.timestamp || "",
        src_ip: a.src_ip || "",
        dst_ip: a.dst_ip || "",
      });
      await fetch(`${API_BASE}/alerts?${p}`, { method: "DELETE" });
      fetchAlerts();
      fetchStats();
    } catch {
      fetchAlerts();
      fetchStats();
    }
  };

  const clearAllAlerts = async () => {
    try {
      await fetch(`${API_BASE}/alerts`, { method: "DELETE" });
      fetchAlerts();
      fetchStats();
      setHistory([]);
      setAnalysis(null);
    } catch {
      fetchAlerts();
      fetchStats();
    }
  };

  const exportAlerts = async (fmt) => {
    try {
      const blob = await (
        await fetch(`${API_BASE}/alerts/export?format=${fmt}`)
      ).blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fmt === "csv" ? "alerts.csv" : "alerts.json";
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert("Export failed: " + e.message);
    }
  };

  const updatePolicy = async () => {
    try {
      await fetch(`${API_BASE}/policy`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          low_threshold: configTemp.low,
          medium_threshold: configTemp.medium,
          high_threshold: configTemp.high,
        }),
      });
      fetchPolicy();
      setShowConfig(false);
    } catch (e) {
      alert(e.message);
    }
  };

  const runDemo = async () => {
    setDemoRunning(true);
    setError(null);
    setAnalysis(null);
    for (const [, preset] of Object.entries(PRESETS)) {
      setFlowForm(preset);
      try {
        const res = await fetch(`${API_BASE}/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(preset),
        });
        if (!res.ok) {
          const errBody = await res.json().catch(() => ({}));
          throw new Error(errBody.detail || `HTTP ${res.status}`);
        }
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        setAnalysis(data);
        setHistory((h) => [
          { ...data, input: { ...preset } },
          ...h.slice(0, 19),
        ]);
        await new Promise((r) => setTimeout(r, 1400));
      } catch (e) {
        setError(e.message || "Demo failed — Is the API running?");
        break;
      }
    }
    setDemoRunning(false);
    fetchAlerts();
    fetchStats();
  };

  const formatExplainValue = (v) => {
    if (typeof v !== "number") v = parseFloat(v) || 0;
    return v <= 1 ? (v * 100).toFixed(0) : v.toFixed(0);
  };

  const riskColor = (score) => getRiskColor(score);

  return (
    <div className="app">
      {/* ── HEADER ── */}
      <header className="header">
        <h1>🛡️ AI-Driven NGFW</h1>
        <p>Dynamic Threat Detection &amp; Zero Trust</p>
        <div className="header-actions">
          <div className="health">
            {health && (
              <span className={health.status === "ok" ? "ok" : "err"}>
                {health.status === "ok" ? "● Online" : "○ Offline"}
                {health.models_loaded && (
                  <small>
                    {" "}
                    RF:{health.models_loaded.random_forest ? "✓" : "✗"} AE:
                    {health.models_loaded.autoencoder ? "✓" : "✗"}
                  </small>
                )}
                {metrics && !metrics.message && (
                  <small className="accuracy-badge">
                    {" "}
                    · {(metrics.accuracy * 100).toFixed(1)}% Acc
                  </small>
                )}
              </span>
            )}
          </div>
          <button
            type="button"
            className="header-btn"
            onClick={() => setShowAbout(true)}
          >
            About
          </button>
          <button
            type="button"
            className="header-btn"
            onClick={() => {
              setShowConfig(true);
              setConfigTemp(
                policy
                  ? {
                      low: policy.low_threshold,
                      medium: policy.medium_threshold,
                      high: policy.high_threshold,
                    }
                  : { low: 0.3, medium: 0.6, high: 0.8 },
              );
            }}
          >
            Config
          </button>
        </div>
      </header>

      <main className="main">
        {/* ── FLOW ANALYSIS ── */}
        <section className="card flow-card">
          <h2>Flow Analysis</h2>
          <div className="presets">
            <span className="preset-label">Presets:</span>
            {Object.entries(PRESETS).map(([key]) => (
              <button
                key={key}
                type="button"
                className="preset-btn"
                onClick={() => applyPreset(key)}
              >
                {key.replace(/([A-Z])/g, " $1").trim()}
              </button>
            ))}
            <button
              type="button"
              className="preset-btn clear-form-btn"
              onClick={() => {
                setFlowForm(emptyForm);
                setAnalysis(null);
                setError(null);
              }}
            >
              Clear Form
            </button>
          </div>

          <div className="form-grid">
            {[
              { label: "Source IP", key: "src_ip", type: "text" },
              { label: "Dest IP", key: "dst_ip", type: "text" },
              {
                label: "Source Port",
                key: "src_port",
                type: "number",
                min: 0,
                max: 65535,
              },
              {
                label: "Dest Port",
                key: "dst_port",
                type: "number",
                min: 0,
                max: 65535,
              },
            ].map(({ label, key, type, min, max }) => (
              <label key={key}>
                <span>{label}</span>
                <input
                  type={type}
                  min={min}
                  max={max}
                  placeholder="0"
                  value={flowForm[key] === "" ? "" : flowForm[key]}
                  onChange={(e) =>
                    setFlowForm({
                      ...flowForm,
                      [key]:
                        type === "number"
                          ? e.target.value === ""
                            ? ""
                            : +e.target.value
                          : e.target.value,
                    })
                  }
                />
              </label>
            ))}
            <label>
              <span>Protocol</span>
              <select
                value={flowForm.protocol}
                onChange={(e) =>
                  setFlowForm({ ...flowForm, protocol: e.target.value })
                }
              >
                <option>TCP</option>
                <option>UDP</option>
                <option>ICMP</option>
              </select>
            </label>
            {[
              { label: "Packet Count", key: "packet_count", step: 1 },
              { label: "Byte Volume", key: "byte_volume", step: 1 },
              { label: "Duration (sec)", key: "duration", step: 0.1 },
              { label: "Fwd/Bwd Ratio", key: "fwd_bwd_ratio", step: 0.1 },
            ].map(({ label, key, step }) => (
              <label key={key}>
                <span>{label}</span>
                <input
                  type="number"
                  step={step}
                  min="0"
                  placeholder="0"
                  value={flowForm[key] === "" ? "" : flowForm[key]}
                  onChange={(e) =>
                    setFlowForm({
                      ...flowForm,
                      [key]: e.target.value === "" ? "" : +e.target.value,
                    })
                  }
                />
              </label>
            ))}
          </div>

          <div className="analyze-row">
            <button
              className="analyze-btn"
              onClick={analyze}
              disabled={loading || demoRunning}
            >
              {loading ? "Analyzing…" : "Analyze Flow"}
            </button>
            <button
              type="button"
              className="demo-btn"
              onClick={runDemo}
              disabled={loading || demoRunning}
            >
              {demoRunning ? "⏳ Demo Running…" : "▶ Demo Mode"}
            </button>
          </div>

          {error && (
            <div className="error-msg">⚠ {error} — Is the API running?</div>
          )}

          {/* ── ANALYSIS RESULT ── */}
          {analysis && !analysis.error && (
            <div
              className="result"
              style={{ borderColor: riskColor(analysis.risk_score) }}
            >
              {/* Risk badge */}
              <div
                className="result-badge"
                style={{
                  background: riskColor(analysis.risk_score) + "22",
                  border: `1px solid ${riskColor(analysis.risk_score)}44`,
                }}
              >
                <span
                  className="risk-pct"
                  style={{ color: riskColor(analysis.risk_score) }}
                >
                  {((analysis.risk_score ?? 0) * 100).toFixed(1)}%
                </span>
                <span
                  className="risk-lbl"
                  style={{ color: riskColor(analysis.risk_score) }}
                >
                  {getRiskLabel(analysis.risk_score)} RISK
                </span>
              </div>

              <div className="result-row">
                <span>Threat Class</span>
                <strong>{analysis.threat_class || "—"}</strong>
              </div>
              <div className="result-row">
                <span>Action</span>
                <strong className={`action-badge action-${analysis.action}`}>
                  {analysis.action || "—"}
                </strong>
              </div>
              <div className="result-row">
                <span>Latency</span>
                <strong>{analysis.policy_latency_ms ?? "—"} ms</strong>
              </div>

              {(() => {
                const expl = analysis.explanation || {};
                const entries = Object.entries(expl).filter(
                  ([k]) => k !== "message",
                );
                if (entries.length === 0) return null;
                const maxVal = Math.max(
                  ...entries.map(([, v]) => parseFloat(v) || 0),
                );
                return (
                  <div className="explanation">
                    <h4>Risk Factors</h4>
                    <div className="bar-chart">
                      {entries
                        .sort(([, a], [, b]) => b - a)
                        .map(([k, v]) => {
                          const pct =
                            maxVal > 0
                              ? ((parseFloat(v) || 0) / maxVal) * 100
                              : 0;
                          const display = ((parseFloat(v) || 0) * 100).toFixed(
                            0,
                          );
                          return (
                            <div key={k} className="bar-row">
                              <span>{k.replace(/_/g, " ")}</span>
                              <div className="bar-wrap">
                                <div
                                  className="bar"
                                  style={{
                                    width: `${pct}%`,
                                    background: riskColor(analysis.risk_score),
                                  }}
                                />
                              </div>
                              <span>{display}%</span>
                            </div>
                          );
                        })}
                    </div>
                  </div>
                );
              })()}
            </div>
          )}
        </section>

        {/* ── ATTACK TIMELINE ── */}
        {history.length > 0 && (
          <section className="card timeline-card">
            <h2>📈 Attack Timeline</h2>
            <p className="card-subtitle">
              Risk score trend across last {history.length} analyses
            </p>
            <TimelineChart history={history} />
          </section>
        )}

        {/* ── STATS + METRICS ── */}
        <div className="stats-row">
          {stats && (
            <section className="card stats-card">
              <h2>Statistics</h2>
              <div className="stats-grid">
                <div className="stat-item">
                  <span className="stat-value">{stats.total_alerts || 0}</span>
                  <span className="stat-label">Total Alerts</span>
                </div>
                <div className="stat-item">
                  <span className="stat-value danger">
                    {stats.high_risk_count || 0}
                  </span>
                  <span className="stat-label">High Risk</span>
                </div>
                <div className="stat-item">
                  <span className="stat-value" style={{ color: "#3b82f6" }}>
                    {history.length}
                  </span>
                  <span className="stat-label">Analyses</span>
                </div>
                {stats.threat_breakdown &&
                  Object.keys(stats.threat_breakdown).length > 0 && (
                    <div className="stat-item wide">
                      <span className="stat-label">Threat Types</span>
                      <div className="threat-tags">
                        {Object.entries(stats.threat_breakdown).map(
                          ([k, v]) => (
                            <span key={k} className="threat-tag">
                              {k}: {v}
                            </span>
                          ),
                        )}
                      </div>
                    </div>
                  )}
              </div>
            </section>
          )}
          {metrics && !metrics.message && (
            <section className="card metrics-card">
              <h2>Model Metrics</h2>
              <div className="metrics-grid">
                <div>
                  <span>Precision</span>
                  <strong style={{ color: "#22c55e" }}>
                    {(metrics.precision * 100).toFixed(1)}%
                  </strong>
                </div>
                <div>
                  <span>Recall</span>
                  <strong style={{ color: "#22c55e" }}>
                    {(metrics.recall * 100).toFixed(1)}%
                  </strong>
                </div>
                <div>
                  <span>F1-Score</span>
                  <strong style={{ color: "#22c55e" }}>
                    {(metrics.f1_score * 100).toFixed(1)}%
                  </strong>
                </div>
                <div>
                  <span>Accuracy</span>
                  <strong style={{ color: "#22c55e" }}>
                    {(metrics.accuracy * 100).toFixed(1)}%
                  </strong>
                </div>
                {metrics.train_samples != null && (
                  <div>
                    <span>Train</span>
                    {metrics.train_samples}
                  </div>
                )}
                {metrics.test_samples != null && (
                  <div>
                    <span>Test</span>
                    {metrics.test_samples}
                  </div>
                )}
              </div>
            </section>
          )}
        </div>

        {/* ── HISTORY TABLE ── */}
        {history.length > 0 && (
          <section className="card history-card">
            <h2>🕒 Analysis History</h2>
            <p className="card-subtitle">
              Last {history.length} flow analyses this session
            </p>
            <HistoryTable history={history} />
          </section>
        )}

        {/* ── SECURITY ALERTS ── */}
        <section className="card alerts-card">
          <div className="alerts-header">
            <h2>🚨 Security Alerts</h2>
            <div className="alerts-actions">
              {alerts.length > 0 && (
                <>
                  <button
                    type="button"
                    className="export-btn"
                    onClick={() => exportAlerts("csv")}
                  >
                    Export CSV
                  </button>
                  <button
                    type="button"
                    className="clear-all-btn"
                    onClick={clearAllAlerts}
                  >
                    Clear All
                  </button>
                </>
              )}
            </div>
          </div>
          <div className="alerts-list">
            {alerts.length === 0 ? (
              <p className="muted">
                No alerts yet. Analyze a suspicious flow to generate alerts.
              </p>
            ) : (
              alerts.slice(0, 15).map((a, i) => (
                <div
                  key={i}
                  className="alert-item"
                  style={{ borderLeftColor: riskColor(a.risk_score) }}
                >
                  <div className="alert-content">
                    <div className="alert-meta">
                      <span>
                        {a.src_ip} → {a.dst_ip}
                      </span>
                      <span
                        className="risk"
                        style={{ color: riskColor(a.risk_score) }}
                      >
                        {((a.risk_score ?? 0) * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="alert-detail">
                      {a.threat_class} · {a.action}
                    </div>
                  </div>
                  <button
                    type="button"
                    className="delete-alert-btn"
                    onClick={() => deleteAlert(a)}
                    title="Delete"
                  >
                    ×
                  </button>
                </div>
              ))
            )}
          </div>
        </section>

        {/* ── ZERO TRUST POLICY ── */}
        {policy && (
          <section className="card policy-card">
            <h2>🔒 Zero Trust Policy</h2>
            <div className="policy-thresholds">
              <div>
                <span>Low</span>
                <strong style={{ color: "#22c55e" }}>
                  &lt; {policy.low_threshold}
                </strong>
                <small>→ Allow</small>
              </div>
              <div>
                <span>Adaptive Auth</span>
                <strong style={{ color: "#3b82f6" }}>
                  {policy.low_threshold} – {policy.medium_threshold}
                </strong>
                <small>→ Adaptive Auth</small>
              </div>
              <div>
                <span>Medium</span>
                <strong style={{ color: "#f59e0b" }}>
                  {policy.medium_threshold} – {policy.high_threshold}
                </strong>
                <small>→ Restrict</small>
              </div>
              <div>
                <span>High</span>
                <strong style={{ color: "#ef4444" }}>
                  &gt; {policy.high_threshold}
                </strong>
                <small>→ Block</small>
              </div>
            </div>
          </section>
        )}
      </main>

      {/* ── ABOUT MODAL ── */}
      {showAbout && (
        <div className="modal-overlay" onClick={() => setShowAbout(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>🛡️ AI-Driven Next-Generation Firewall</h3>
            <p>
              <strong>
                Dynamic Threat Detection &amp; Zero Trust Implementation
              </strong>
            </p>
            <p>
              Final Year Project — IIMT College of Engineering, Greater Noida
            </p>
            <p style={{ color: "#888", fontSize: "0.85rem" }}>
              Based on IJRIAS Volume X, Issue XII (2025)
            </p>
            <ul>
              <li>
                Random Forest — known attack classification (DoS, Probe, Brute
                Force)
              </li>
              <li>
                Autoencoder / IsolationForest — zero-day anomaly detection
              </li>
              <li>Zero Trust policy engine with dynamic risk scoring</li>
              <li>Explainable AI — risk factor breakdown per decision</li>
              <li>Model Accuracy: 94.2% | Precision: 94.2% | F1: 94.1%</li>
            </ul>
            <button
              type="button"
              className="modal-close"
              onClick={() => setShowAbout(false)}
            >
              Close
            </button>
          </div>
        </div>
      )}

      {/* ── CONFIG MODAL ── */}
      {showConfig && (
        <div className="modal-overlay" onClick={() => setShowConfig(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Policy Thresholds</h3>
            <p
              style={{
                color: "#888",
                fontSize: "0.82rem",
                marginBottom: "1rem",
              }}
            >
              Risk score ranges: Low → Allow, Medium → Restrict, High → Block
            </p>
            <label>
              Low Threshold
              <input
                type="number"
                step="0.1"
                min="0"
                max="1"
                value={configTemp.low}
                onChange={(e) =>
                  setConfigTemp({ ...configTemp, low: +e.target.value })
                }
              />
            </label>
            <label>
              Medium Threshold
              <input
                type="number"
                step="0.1"
                min="0"
                max="1"
                value={configTemp.medium}
                onChange={(e) =>
                  setConfigTemp({ ...configTemp, medium: +e.target.value })
                }
              />
            </label>
            <label>
              High Threshold
              <input
                type="number"
                step="0.1"
                min="0"
                max="1"
                value={configTemp.high}
                onChange={(e) =>
                  setConfigTemp({ ...configTemp, high: +e.target.value })
                }
              />
            </label>
            <div className="modal-actions">
              <button type="button" onClick={updatePolicy}>
                Save
              </button>
              <button
                type="button"
                className="modal-close"
                onClick={() => setShowConfig(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
