import { useState, useRef } from 'react'
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'

const API_BASE = '/api'
const SEVERITY_COLORS = {
  CRITICAL: '#f87171', HIGH: '#fb923c', MEDIUM: '#fbbf24',
  LOW: '#a3e635', UNKNOWN: '#94a3b8',
}

export default function App() {
  const [imageName, setImageName] = useState('')
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(false)
  const pollRef = useRef(null)

  async function startScan(e) {
    e.preventDefault()
    if (!imageName.trim()) return
    setLoading(true)
    setScan(null)

    const res = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image_name: imageName.trim() }),
    })
    const data = await res.json()
    setScan(data)
    pollStatus(data.id)
  }

  function pollStatus(scanId) {
    clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      const res = await fetch(`${API_BASE}/scan/${scanId}`)
      if (!res.ok) return
      const data = await res.json()
      setScan(data)
      if (data.status === 'done' || data.status === 'failed') {
        clearInterval(pollRef.current)
        setLoading(false)
      }
    }, 3000)
  }

  const severityCounts = scan?.vulnerabilities?.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1
    return acc
  }, {}) || {}
  const chartData = Object.entries(severityCounts).map(([name, value]) => ({ name, value }))

  return (
    <div className="container">
      <h1>🛡️ ContainerShield AI</h1>
      <p className="subtitle">Docker image security scanner — CVEs, secrets & SBOM in one place</p>

      <form className="scan-form" onSubmit={startScan}>
        <input
          type="text"
          placeholder="e.g. nginx:latest"
          value={imageName}
          onChange={(e) => setImageName(e.target.value)}
        />
        <button type="submit" disabled={loading}>
          {loading ? 'Scanning...' : 'Scan Image'}
        </button>
      </form>

      {!scan && <div className="empty-state">Enter a Docker image name above to start a scan.</div>}

      {scan && (
        <>
          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div><strong>{scan.image_name}</strong></div>
                <span className={`status-pill status-${scan.status}`}>{scan.status}</span>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div className="risk-score">{scan.risk_score ?? 0}</div>
                <div style={{ fontSize: 12, color: '#94a3b8' }}>risk score / 100</div>
              </div>
            </div>
            {scan.status === 'failed' && (
              <p style={{ color: '#fca5a5', marginTop: 10 }}>Error: {scan.error_message}</p>
            )}
            {scan.status === 'done' && (
              <button
                className="report-btn"
                onClick={() => window.open(`${API_BASE}/scan/${scan.id}/report`, '_blank')}
              >
                Download PDF Report
              </button>
            )}
          </div>

          {scan.vulnerabilities?.length > 0 && (
            <div className="card">
              <h3>Vulnerability Breakdown</h3>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={chartData} dataKey="value" nameKey="name" outerRadius={80} label>
                    {chartData.map((entry, i) => (
                      <Cell key={i} fill={SEVERITY_COLORS[entry.name] || '#94a3b8'} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>

              <table>
                <thead>
                  <tr>
                    <th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Severity</th><th>Tool</th>
                  </tr>
                </thead>
                <tbody>
                  {scan.vulnerabilities.slice(0, 50).map((v, i) => (
                    <tr key={i}>
                      <td>{v.cve_id}</td>
                      <td>{v.package}</td>
                      <td>{v.installed_version || '-'}</td>
                      <td>{v.fixed_version || '-'}</td>
                      <td className={`sev-${v.severity}`}>{v.severity}</td>
                      <td>{v.source_tool}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {scan.secrets?.length > 0 && (
            <div className="card">
              <h3>🔑 Exposed Secrets ({scan.secrets.length})</h3>
              <table>
                <thead><tr><th>File</th><th>Rule</th><th>Match</th></tr></thead>
                <tbody>
                  {scan.secrets.map((s, i) => (
                    <tr key={i}><td>{s.file_path}</td><td>{s.rule_id}</td><td>{s.match_snippet}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {scan.sbom_components?.length > 0 && (
            <div className="card">
              <h3>📦 SBOM ({scan.sbom_components.length} components)</h3>
              <table>
                <thead><tr><th>Component</th><th>Version</th><th>Type</th></tr></thead>
                <tbody>
                  {scan.sbom_components.slice(0, 30).map((c, i) => (
                    <tr key={i}><td>{c.component_name}</td><td>{c.version || '-'}</td><td>{c.component_type || '-'}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  )
}
