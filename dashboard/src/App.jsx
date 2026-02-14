import { useState, useEffect, useCallback } from 'react'
import './App.css'

// Support both Vite proxy (/api) and direct API URL
const API_BASE = import.meta.env.VITE_API_URL || '/api'

const PRESETS = {
  normal: {
    src_ip: '192.168.1.10',
    dst_ip: '8.8.8.8',
    src_port: 54321,
    dst_port: 443,
    protocol: 'TCP',
    packet_count: 80,
    byte_volume: 12000,
    duration: 5.0,
    fwd_bwd_ratio: 1.2,
  },
  ddos: {
    src_ip: '10.0.0.1',
    dst_ip: '192.168.1.1',
    src_port: 12345,
    dst_port: 80,
    protocol: 'TCP',
    packet_count: 50000,
    byte_volume: 5000000,
    duration: 2.0,
    fwd_bwd_ratio: 10.0,
  },
  suspicious: {
    src_ip: '192.168.1.50',
    dst_ip: '10.0.0.100',
    src_port: 33333,
    dst_port: 3306,
    protocol: 'TCP',
    packet_count: 5000,
    byte_volume: 200000,
    duration: 0.5,
    fwd_bwd_ratio: 5.0,
  },
  bruteForce: {
    src_ip: '203.0.113.1',
    dst_ip: '192.168.1.10',
    src_port: 49152,
    dst_port: 22,
    protocol: 'TCP',
    packet_count: 2000,
    byte_volume: 50000,
    duration: 10.0,
    fwd_bwd_ratio: 0.2,
  },
}

const emptyForm = {
  src_ip: '',
  dst_ip: '',
  src_port: '',
  dst_port: '',
  protocol: 'TCP',
  packet_count: '',
  byte_volume: '',
  duration: '',
  fwd_bwd_ratio: '',
}

const defaultForm = {
  src_ip: '192.168.1.10',
  dst_ip: '8.8.8.8',
  src_port: 54321,
  dst_port: 443,
  protocol: 'TCP',
  packet_count: 100,
  byte_volume: 10000,
  duration: 5.2,
  fwd_bwd_ratio: 1.0,
}

function App() {
  const [history, setHistory] = useState([]);
  const [health, setHealth] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [metrics, setMetrics] = useState(null)
  const [policy, setPolicy] = useState(null)
  const [flowForm, setFlowForm] = useState(defaultForm)
  const [analysis, setAnalysis] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [showAbout, setShowAbout] = useState(false)
  const [showConfig, setShowConfig] = useState(false)
  const [configTemp, setConfigTemp] = useState({ low: 0.3, medium: 0.6, high: 0.8 })
  const [demoRunning, setDemoRunning] = useState(false)

  const fetchHealth = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/health`)
      const data = await r.json()
      setHealth(data)
    } catch (e) {
      setHealth({ status: 'error' })
    }
  }, [])

  const fetchAlerts = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/alerts?limit=50`)
      const d = await r.json()
      const list = (d.alerts || []).filter(
        (v, i, arr) =>
          i === arr.findIndex((x) => x.timestamp === v.timestamp && x.src_ip === v.src_ip && x.dst_ip === v.dst_ip)
      )
      setAlerts(list)
    } catch {
      setAlerts([])
    }
  }, [])

  const deleteAlert = async (a) => {
    try {
      const params = new URLSearchParams({ timestamp: a.timestamp || '', src_ip: a.src_ip || '', dst_ip: a.dst_ip || '' })
      await fetch(`${API_BASE}/alerts?${params}`, { method: 'DELETE' })
      fetchAlerts()
    } catch {
      fetchAlerts()
    }
  }

  const clearAllAlerts = async () => {
    try {
      await fetch(`${API_BASE}/alerts`, { method: 'DELETE' })
      fetchAlerts()
    } catch {
      fetchAlerts()
    }
  }

  const fetchPolicy = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/policy`)
      const data = await r.json()
      setPolicy(data)
    } catch {
      setPolicy(null)
    }
  }, [])

  useEffect(() => {
    fetchHealth()
  }, [fetchHealth])

  const fetchStats = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/stats`)
      setStats(await r.json())
    } catch { setStats(null) }
  }, [])

  const fetchMetrics = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/model/metrics`)
      setMetrics(await r.json())
    } catch { setMetrics(null) }
  }, [])

  useEffect(() => {
    fetchAlerts()
    fetchPolicy()
    fetchStats()
    fetchMetrics()
    const id = setInterval(() => {
      fetchAlerts()
      fetchPolicy()
      fetchStats()
    }, 4000)
    return () => clearInterval(id)
  }, [fetchAlerts, fetchPolicy, fetchStats, fetchMetrics])

  useEffect(() => { fetchMetrics() }, [fetchMetrics])

  const applyPreset = (key) => {
    setFlowForm(PRESETS[key] || defaultForm)
    setAnalysis(null)
    setError(null)
  }

  const analyze = async () => {
    setLoading(true)
    setAnalysis(null)
    setError(null)
    try {
      const payload = {
        ...flowForm,
        src_port: flowForm.src_port === '' ? 0 : (Number(flowForm.src_port) || 0),
        dst_port: flowForm.dst_port === '' ? 0 : (Number(flowForm.dst_port) || 0),
        packet_count: flowForm.packet_count === '' ? 0 : (Number(flowForm.packet_count) || 0),
        byte_volume: flowForm.byte_volume === '' ? 0 : (Number(flowForm.byte_volume) || 0),
        duration: flowForm.duration === '' ? 0 : (Number(flowForm.duration) || 0),
        fwd_bwd_ratio: flowForm.fwd_bwd_ratio === '' ? 1 : (Number(flowForm.fwd_bwd_ratio) || 1),
      }
      const res = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setAnalysis(data)
      setHistory((h) => [{ ...data, input: { ...flowForm } }, ...h.slice(0, 9)])
    } catch (e) {
      setError(e.message || 'Failed to analyze')
      setAnalysis(null)
    } finally {
      setLoading(false)
    }
  }

  const riskColor = (score) => {
    if (score == null) return 'var(--text-muted)'
    if (score < 0.3) return 'var(--success)'
    if (score < 0.6) return 'var(--warning)'
    return 'var(--danger)'
  }

  const formatExplainValue = (v) => {
    if (typeof v !== 'number') v = parseFloat(v) || 0
    return v <= 1 ? (v * 100).toFixed(0) : v.toFixed(0)
  }

  const exportAlerts = async (fmt) => {
    try {
      const r = await fetch(`${API_BASE}/alerts/export?format=${fmt}`)
      const blob = await r.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = fmt === 'csv' ? 'alerts.csv' : 'alerts.json'
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) { alert('Export failed: ' + e.message) }
  }

  const updatePolicy = async () => {
    try {
      await fetch(`${API_BASE}/policy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          low_threshold: configTemp.low,
          medium_threshold: configTemp.medium,
          high_threshold: configTemp.high,
        }),
      })
      fetchPolicy()
      setShowConfig(false)
    } catch (e) { alert(e.message) }
  }

  const runDemo = async () => {
    setDemoRunning(true)
    setError(null)
    for (const [key, preset] of Object.entries(PRESETS)) {
      setFlowForm(preset)
      try {
        const payload = { ...preset }
        const res = await fetch(`${API_BASE}/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        })
        const data = await res.json()
        setAnalysis(data)
        await new Promise((r) => setTimeout(r, 1200))
      } catch (e) {
        setError(e.message)
        break
      }
    }
    setDemoRunning(false)
    fetchAlerts()
    fetchStats()
  }

  return (
    <div className="app">
      <header className="header">
        <h1>AI-Driven NGFW</h1>
        <p>Dynamic Threat Detection & Zero Trust</p>
        <div className="header-actions">
          <div className="health">
            {health && (
              <span className={health.status === 'ok' ? 'ok' : 'err'}>
                {health.status === 'ok' ? '● Online' : '○ Offline'}
                {health.models_loaded && (
                  <small> RF:{health.models_loaded.random_forest ? '✓' : '✗'} AE:{health.models_loaded.autoencoder ? '✓' : '✗'}</small>
                )}
              </span>
            )}
          </div>
          <button type="button" className="header-btn" onClick={() => setShowAbout(true)}>About</button>
          <button type="button" className="header-btn" onClick={() => { setShowConfig(true); setConfigTemp(policy ? { low: policy.low_threshold, medium: policy.medium_threshold, high: policy.high_threshold } : { low: 0.3, medium: 0.6, high: 0.8 }); }}>Config</button>
        </div>
      </header>

      <main className="main">
        <section className="card flow-card">
          <h2>Flow Analysis</h2>

          <div className="presets">
            <span className="preset-label">Presets:</span>
            {Object.entries(PRESETS).map(([key, _]) => (
              <button key={key} type="button" className="preset-btn" onClick={() => applyPreset(key)}>
                {key.replace(/([A-Z])/g, ' $1').trim()}
              </button>
            ))}
            <button type="button" className="preset-btn clear-form-btn" onClick={() => { setFlowForm(emptyForm); setAnalysis(null); setError(null); }}>
              Clear Form
            </button>
          </div>

          <div className="form-grid">
            <label>
              <span>Source IP</span>
              <input placeholder="" value={flowForm.src_ip} onChange={(e) => setFlowForm({ ...flowForm, src_ip: e.target.value })} />
            </label>
            <label>
              <span>Dest IP</span>
              <input placeholder="" value={flowForm.dst_ip} onChange={(e) => setFlowForm({ ...flowForm, dst_ip: e.target.value })} />
            </label>
            <label>
              <span>Source Port</span>
              <input
                type="number"
                min="0"
                max="65535"
                placeholder="0"
                value={flowForm.src_port === '' ? '' : flowForm.src_port}
                onChange={(e) => setFlowForm({ ...flowForm, src_port: e.target.value === '' ? '' : +e.target.value })}
              />
            </label>
            <label>
              <span>Dest Port</span>
              <input
                type="number"
                min="0"
                max="65535"
                placeholder="0"
                value={flowForm.dst_port === '' ? '' : flowForm.dst_port}
                onChange={(e) => setFlowForm({ ...flowForm, dst_port: e.target.value === '' ? '' : +e.target.value })}
              />
            </label>
            <label>
              <span>Protocol</span>
              <select value={flowForm.protocol} onChange={(e) => setFlowForm({ ...flowForm, protocol: e.target.value })}>
                <option>TCP</option>
                <option>UDP</option>
                <option>ICMP</option>
              </select>
            </label>
            <label>
              <span>Packet Count</span>
              <input
                type="number"
                min="0"
                placeholder="0"
                value={flowForm.packet_count === '' ? '' : flowForm.packet_count}
                onChange={(e) => setFlowForm({ ...flowForm, packet_count: e.target.value === '' ? '' : +e.target.value })}
              />
            </label>
            <label>
              <span>Byte Volume</span>
              <input
                type="number"
                min="0"
                placeholder="0"
                value={flowForm.byte_volume === '' ? '' : flowForm.byte_volume}
                onChange={(e) => setFlowForm({ ...flowForm, byte_volume: e.target.value === '' ? '' : +e.target.value })}
              />
            </label>
            <label>
              <span>Duration (sec)</span>
              <input
                type="number"
                step="0.1"
                min="0"
                placeholder="0"
                value={flowForm.duration === '' ? '' : flowForm.duration}
                onChange={(e) => setFlowForm({ ...flowForm, duration: e.target.value === '' ? '' : +e.target.value })}
              />
            </label>
            <label>
              <span>Fwd/Bwd Ratio</span>
              <input
                type="number"
                step="0.1"
                min="0"
                placeholder="0"
                value={flowForm.fwd_bwd_ratio === '' ? '' : flowForm.fwd_bwd_ratio}
                onChange={(e) => setFlowForm({ ...flowForm, fwd_bwd_ratio: e.target.value === '' ? '' : +e.target.value })}
              />
            </label>
          </div>

          <div className="analyze-row">
            <button className="analyze-btn" onClick={analyze} disabled={loading || demoRunning}>
              {loading ? 'Analyzing…' : 'Analyze Flow'}
            </button>
            <button type="button" className="demo-btn" onClick={runDemo} disabled={loading || demoRunning} title="Run through all presets">
              {demoRunning ? 'Demo…' : '▶ Demo Mode'}
            </button>
          </div>

          {error && (
            <div className="error-msg">
              {error} — Is the API running on port 8000?
            </div>
          )}

          {analysis && !analysis.error && (
            <div className="result" style={{ borderColor: riskColor(analysis.risk_score) }}>
              <div className="result-row">
                <span>Risk Score</span>
                <strong style={{ color: riskColor(analysis.risk_score) }}>
                  {((analysis.risk_score ?? 0) * 100).toFixed(1)}%
                </strong>
              </div>
              <div className="result-row">
                <span>Threat Class</span>
                <strong>{analysis.threat_class || '—'}</strong>
              </div>
              <div className="result-row">
                <span>Action</span>
                <strong>{analysis.action || '—'}</strong>
              </div>
              <div className="result-row">
                <span>Latency</span>
                <strong>{analysis.policy_latency_ms ?? '—'} ms</strong>
              </div>
              {analysis.explanation && Object.keys(analysis.explanation).length > 0 && (
                <div className="explanation">
                  <h4>Risk Factors</h4>
                  <div className="bar-chart">
                    {Object.entries(analysis.explanation).map(([k, v]) => (
                      <div key={k} className="bar-row">
                        <span>{k.replace(/_/g, ' ')}</span>
                        <div className="bar-wrap">
                          <div
                            className="bar"
                            style={{
                              width: `${Math.min(100, formatExplainValue(v))}%`,
                            }}
                          />
                        </div>
                        <span>{formatExplainValue(v)}%</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </section>

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
                  <span className="stat-value danger">{stats.high_risk_count || 0}</span>
                  <span className="stat-label">High Risk</span>
                </div>
                {stats.threat_breakdown && Object.keys(stats.threat_breakdown).length > 0 && (
                  <div className="stat-item wide">
                    <span className="stat-label">Threat Types</span>
                    <div className="threat-tags">
                      {Object.entries(stats.threat_breakdown).map(([k, v]) => (
                        <span key={k} className="threat-tag">{k}: {v}</span>
                      ))}
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
                <div><span>Precision</span>{(metrics.precision * 100).toFixed(1)}%</div>
                <div><span>Recall</span>{(metrics.recall * 100).toFixed(1)}%</div>
                <div><span>F1-Score</span>{(metrics.f1_score * 100).toFixed(1)}%</div>
                <div><span>Accuracy</span>{(metrics.accuracy * 100).toFixed(1)}%</div>
                {metrics.train_samples != null && <div><span>Train</span>{metrics.train_samples}</div>}
                {metrics.test_samples != null && <div><span>Test</span>{metrics.test_samples}</div>}
              </div>
            </section>
          )}
        </div>

        <section className="card alerts-card">
          <div className="alerts-header">
            <h2>Security Alerts</h2>
            <div className="alerts-actions">
              {alerts.length > 0 && (
                <>
                  <button type="button" className="export-btn" onClick={() => exportAlerts('csv')} title="Export CSV">
                    Export CSV
                  </button>
                  <button type="button" className="clear-all-btn" onClick={clearAllAlerts} title="Clear all">
                    Clear All
                  </button>
                </>
              )}
            </div>
          </div>
          <div className="alerts-list">
            {alerts.length === 0 ? (
              <p className="muted">No alerts yet. Analyze a suspicious flow to generate alerts.</p>
            ) : (
              alerts.slice(0, 15).map((a, i) => (
                <div key={i} className="alert-item" style={{ borderLeftColor: riskColor(a.risk_score) }}>
                  <div className="alert-content">
                    <div className="alert-meta">
                      <span>
                        {a.src_ip} → {a.dst_ip}
                      </span>
                      <span className="risk" style={{ color: riskColor(a.risk_score) }}>
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
                    title="Delete alert"
                    aria-label="Delete"
                  >
                    ×
                  </button>
                </div>
              ))
            )}
          </div>
        </section>

        {policy && (
          <section className="card policy-card">
            <h2>Zero Trust Policy</h2>
            <div className="policy-thresholds">
              <div><span>Low</span>{policy.low_threshold}</div>
              <div><span>Medium</span>{policy.medium_threshold}</div>
              <div><span>High</span>{policy.high_threshold}</div>
            </div>
          </section>
        )}
      </main>

      {showAbout && (
        <div className="modal-overlay" onClick={() => setShowAbout(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>AI-Driven Next-Generation Firewall</h3>
            <p><strong>Dynamic Threat Detection & Zero Trust Implementation</strong></p>
            <p>Final Year Project — IIMT College of Engineering, Greater Noida</p>
            <p>Based on research: IJRIAS Volume X, Issue XII (2025)</p>
            <ul>
              <li>Random Forest for known attack classification</li>
              <li>Autoencoder/IsolationForest for anomaly detection</li>
              <li>Zero Trust policy engine with dynamic risk scoring</li>
              <li>Explainable AI for security decisions</li>
            </ul>
            <button type="button" className="modal-close" onClick={() => setShowAbout(false)}>Close</button>
          </div>
        </div>
      )}

      {showConfig && (
        <div className="modal-overlay" onClick={() => setShowConfig(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Policy Thresholds</h3>
            <label>Low <input type="number" step="0.1" value={configTemp.low} onChange={(e) => setConfigTemp({ ...configTemp, low: +e.target.value })} /></label>
            <label>Medium <input type="number" step="0.1" value={configTemp.medium} onChange={(e) => setConfigTemp({ ...configTemp, medium: +e.target.value })} /></label>
            <label>High <input type="number" step="0.1" value={configTemp.high} onChange={(e) => setConfigTemp({ ...configTemp, high: +e.target.value })} /></label>
            <div className="modal-actions">
              <button type="button" onClick={updatePolicy}>Save</button>
              <button type="button" className="modal-close" onClick={() => setShowConfig(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default App
