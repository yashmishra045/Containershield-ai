import { useEffect, useRef, useState } from 'react'
import './app.css'
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

const API_BASE = '/api'

const COLORS = {
  CRITICAL: '#ff3b4d',
  HIGH: '#ff7a18',
  MEDIUM: '#ffc42e',
  LOW: '#22c997',
  UNKNOWN: '#64748b',
}

const NAV_ITEMS = [
  { key: 'dashboard', label: 'Dashboard', icon: '⌂' },
  { key: 'scanner', label: 'Image Scanner', icon: '⌕' },
  { key: 'vulns', label: 'Vulnerabilities', icon: '♢' },
  { key: 'sbom', label: 'SBOM', icon: '◇' },
  { key: 'history', label: 'Scan History', icon: '◷' },
  { key: 'settings', label: 'Settings', icon: '⚙' },
]

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [imageName, setImageName] = useState('nginx:latest')
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('csai-theme') || 'dark' } catch { return 'dark' }
  })
  const pollRef = useRef(null)

  useEffect(() => {
    try { localStorage.setItem('csai-theme', theme) } catch { /* storage may be unavailable */ }
  }, [theme])

  useEffect(() => {
    return () => clearInterval(pollRef.current)
  }, [])

  async function startScan(e) {
    e.preventDefault()

    if (!imageName.trim()) {
      setError('Please enter a Docker image name')
      return
    }

    setLoading(true)
    setError('')
    setScan(null)

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          image_name: imageName.trim(),
        }),
      })

      if (!res.ok) {
        throw new Error('Unable to start scan')
      }

      const data = await res.json()

      setScan(data)
      pollStatus(data.id)
    } catch (err) {
      setError(err.message || 'Unable to start scan')
      setLoading(false)
    }
  }

  function pollStatus(id) {
    clearInterval(pollRef.current)

    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/scan/${id}`)

        if (!res.ok) return

        const data = await res.json()
        setScan(data)

        if (
          data.status === 'done' ||
          data.status === 'failed'
        ) {
          clearInterval(pollRef.current)
          setLoading(false)
        }
      } catch (err) {
        console.error(err)
      }
    }, 3000)
  }

  const vulnerabilities = scan?.vulnerabilities || []
  const secrets = scan?.secrets || []
  const sbom = scan?.sbom_components || []

  const counts = vulnerabilities.reduce((acc, item) => {
    const severity = item.severity || 'UNKNOWN'
    acc[severity] = (acc[severity] || 0) + 1
    return acc
  }, {})

  const total = vulnerabilities.length

  const chartData = Object.entries(counts).map(
    ([name, value]) => ({
      name,
      value,
    })
  )

  const riskScore = scan?.risk_score ?? 0

  function riskText(score) {
    if (score >= 70) return 'High Risk'
    if (score >= 40) return 'Medium Risk'
    return 'Low Risk'
  }

  // when clicking a nav item that isn't a simple tab, jump to
  // dashboard's scan form so the user always lands somewhere useful
  function goToScanner() {
    setActiveTab('dashboard')
    setTimeout(() => {
      document.querySelector('.input-wrapper input')?.focus()
    }, 0)
  }

  return (
    <div className="app" data-theme={theme}>

      {/* ================= SIDEBAR ================= */}

      <aside className="sidebar">

        <div className="brand">
          <div className="brand-shield">
            🛡
          </div>

          <div>
            <div className="brand-name">
              ContainerShield <span>AI</span>
            </div>

            <div className="brand-sub">
              CONTAINER SECURITY PLATFORM
            </div>
          </div>
        </div>

        <nav className="navigation">
          {NAV_ITEMS.map((item) => (
            <div
              key={item.key}
              className={`nav-item ${activeTab === item.key ? 'active' : ''}`}
              onClick={() => setActiveTab(item.key)}
            >
              <span>{item.icon}</span>
              {item.label}
            </div>
          ))}
        </nav>

        <div className="sidebar-bottom">

          <div className="system-status">
            <span className="online-dot"></span>

            <div>
              <div>System Status</div>
              <strong>Scanner Online</strong>
            </div>
          </div>

          <div className="sidebar-version">
            ContainerShield AI v1.0
          </div>

          <div className="sidebar-description">
            Secure Containers
            <br />
            Safer Deployments
          </div>

        </div>

      </aside>

      {/* ================= MAIN ================= */}

      <main className="main">

        {/* TOP BAR */}

        <header className="topbar">

          <div className="welcome">
            Welcome to
          </div>

          <div className="top-actions">
            <span className="notification">♧</span>

            <div className="user-avatar">
              YM
            </div>

            <span className="username">
              Yash Mishra
            </span>

            <span className="dropdown">
              ▾
            </span>
          </div>

        </header>

        {activeTab === 'dashboard' && (
          <>
            {/* ================= HERO ================= */}

            <section className="hero">

              <div className="hero-content">

                <div className="hero-eyebrow">
                  <span className="hero-eyebrow-dot"></span>
                  AI-Powered Container Security
                </div>

                <h1 className="hero-headline">
                  Secure your container images
                  <br />
                  <span>before they reach production.</span>
                </h1>

                <p className="hero-subtitle">
                  Scan Docker images for vulnerabilities, exposed secrets and
                  software components with ContainerShield AI.
                </p>

              </div>

              <div className="hero-art">
                <div className="hero-shield">
                  🛡
                </div>
              </div>

            </section>

            {/* ================= LIVE STATS ================= */}

            <section className="stats-strip">

              <div className="stat-block">
                <div className="stat-block-num">142</div>
                <div className="stat-block-lbl">Images Scanned</div>
                <div className="stat-block-sub">+6 this week</div>
              </div>

              <div className="stat-block">
                <div className="stat-block-num bad">
                  {counts.CRITICAL || 0}
                </div>
                <div className="stat-block-lbl">Critical Vulns Open</div>
                <div className="stat-block-sub">from last scan</div>
              </div>

              <div className="stat-block">
                <div className="stat-block-num good">96%</div>
                <div className="stat-block-lbl">Avg. Scan Success</div>
                <div className="stat-block-sub">Last 30 days</div>
              </div>

              <div className="stat-block">
                <div className="stat-block-num">
                  {scan ? scan.image_name : '—'}
                </div>
                <div className="stat-block-lbl">Last Scan</div>
                <div className="stat-block-sub">
                  {scan ? scan.status : 'no scans yet'}
                </div>
              </div>

            </section>

            {/* ================= SCANNER ================= */}

            <section className="scanner-card">

              <div className="scanner-title">

                <div className="scanner-icon">
                  ◇
                </div>

                <div>
                  <h2>Scan a Docker Image</h2>

                  <p>
                    Enter a Docker image name to scan for
                    vulnerabilities, secrets and generate SBOM.
                  </p>
                </div>

              </div>

              <form
                className="scanner-form"
                onSubmit={startScan}
              >

                <div className="input-wrapper">

                  <span className="input-icon">
                    ◉
                  </span>

                  <input
                    value={imageName}
                    onChange={(e) =>
                      setImageName(e.target.value)
                    }
                    placeholder="e.g. nginx:latest, redis:7, python:3.11"
                    disabled={loading}
                  />

                </div>

                <button
                  type="submit"
                  disabled={loading}
                >
                  {loading
                    ? 'Scanning...'
                    : 'Scan Image  →'}
                </button>

              </form>

              <div className="scan-features">

                <span>✓ Vulnerability Detection</span>
                <span>✓ Secret Scanning</span>
                <span>✓ SBOM Generation</span>
                <span>✓ Risk Analysis</span>

              </div>

              {loading && (
                <div className="scan-progress" role="status" aria-live="polite">
                  <div className="scan-progress-heading">
                    <span className="loading-spinner" aria-hidden="true" />
                    <div>
                      <strong>Security scan in progress</strong>
                      <p>Scanning <b>{imageName.trim()}</b>. Large images may take a few minutes.</p>
                    </div>
                  </div>
                  <div className="progress-track" aria-label="Scan is running; exact percentage is not provided by the backend">
                    <span className="progress-indeterminate" />
                  </div>
                  <div className="pipeline-list">
                    <span className="pipeline-pill active"><i /> Trivy</span>
                    <span className="pipeline-pill active"><i /> Grype</span>
                    <span className="pipeline-pill active"><i /> Gitleaks</span>
                    <span className="pipeline-pill active"><i /> Syft</span>
                  </div>
                  <p className="progress-note">The API currently reports overall scan status, not per-tool completion or a real percentage. This indicator is intentionally indeterminate rather than showing a made-up progress value.</p>
                </div>
              )}

            </section>

            {/* ================= ERROR ================= */}

            {error && (
              <div className="scan-error">
                <strong>Scan Error</strong>
                <span>{error}</span>
              </div>
            )}

            {/* ================= EMPTY ================= */}

            {!scan && !error && (
              <section className="ready-card">

                <div className="ready-icon">
                  ⌁
                </div>

                <h3>
                  Ready to secure your image
                </h3>

                <p>
                  Enter a Docker image above and start your
                  first security scan.
                </p>

              </section>
            )}

            {/* ================= SCAN RESULTS ================= */}

            {scan && (
              <>

                {/* RESULT HEADER */}

                <section className="result-header-card">

                  <div>
                    <div className="small-label">
                      SCAN RESULT
                    </div>

                    <h2>{scan.image_name}</h2>

                    <span
                      className={`status status-${scan.status}`}
                    >
                      {scan.status}
                    </span>
                  </div>

                  <div
                    className="result-risk-ring"
                    style={{ '--risk': `${Math.min(riskScore, 100) * 3.6}deg` }}
                  >
                    <div className="result-risk-ring-inner">
                      <strong>{riskScore}</strong>
                      <small>/ 100</small>
                    </div>
                  </div>

                </section>

                {scan.status === 'failed' && (
                  <div className="scan-error scan-error-result">
                    <strong>Scan failed</strong>
                    <span>{scan.error_message || 'The backend reported that the scan failed. Check backend logs for the detailed cause.'}</span>
                  </div>
                )}

                {scan.status === 'done' && (
                  <>

                    {/* ================= STATS ================= */}

                    <section className="stats-grid">

                      <StatCard
                        icon="🛡"
                        title="Total Vulnerabilities"
                        value={total}
                        type="blue"
                      />

                      <StatCard
                        icon="!"
                        title="Critical"
                        value={counts.CRITICAL || 0}
                        type="critical"
                      />

                      <StatCard
                        icon="▲"
                        title="High"
                        value={counts.HIGH || 0}
                        type="high"
                      />

                      <StatCard
                        icon="●"
                        title="Medium"
                        value={counts.MEDIUM || 0}
                        type="medium"
                      />

                      <StatCard
                        icon="⬟"
                        title="Low"
                        value={counts.LOW || 0}
                        type="low"
                      />

                    </section>

                    {/* ================= DASHBOARD GRID ================= */}

                    <section className="dashboard-grid">

                      {/* VULNERABILITY BREAKDOWN */}

                      <div className="panel">

                        <div className="panel-title">
                          <span>▥</span>
                          Vulnerability Breakdown
                        </div>

                        {chartData.length > 0 ? (
                          <div className="chart-area">

                            <div className="donut">

                              <ResponsiveContainer
                                width="100%"
                                height={240}
                              >
                                <PieChart>

                                  <Pie
                                    data={chartData}
                                    dataKey="value"
                                    nameKey="name"
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={55}
                                    outerRadius={90}
                                    paddingAngle={1}
                                  >

                                    {chartData.map(
                                      (entry, index) => (
                                        <Cell
                                          key={index}
                                          fill={
                                            COLORS[entry.name] ||
                                            COLORS.UNKNOWN
                                          }
                                        />
                                      )
                                    )}

                                  </Pie>

                                  <Tooltip />

                                </PieChart>
                              </ResponsiveContainer>

                              <div className="donut-center">
                                <strong>{total}</strong>
                                <span>Total</span>
                              </div>

                            </div>

                            <div className="legend">

                              {[
                                ['CRITICAL', counts.CRITICAL || 0],
                                ['HIGH', counts.HIGH || 0],
                                ['MEDIUM', counts.MEDIUM || 0],
                                ['LOW', counts.LOW || 0],
                              ].map(([name, value]) => (

                                <div
                                  className="legend-row"
                                  key={name}
                                >
                                  <span
                                    className="legend-dot"
                                    style={{
                                      background:
                                        COLORS[name],
                                    }}
                                  ></span>

                                  <span>{name}</span>

                                  <strong>{value}</strong>
                                </div>

                              ))}

                            </div>

                          </div>
                        ) : (
                          <div className="no-data">
                            No vulnerabilities detected
                          </div>
                        )}

                      </div>

                      {/* SCAN SUMMARY */}

                      <div className="panel">

                        <div className="panel-title">
                          <span>▤</span>
                          Scan Summary
                        </div>

                        <div className="summary-content">

                          <SummaryRow
                            icon="◉"
                            label="Image Name"
                            value={scan.image_name}
                          />

                          <SummaryRow
                            icon="◎"
                            label="Scan ID"
                            value={scan.id}
                          />

                          <SummaryRow
                            icon="◉"
                            label="Status"
                            value={
                              <span className="completed">
                                Completed
                              </span>
                            }
                          />

                          <SummaryRow
                            icon="♢"
                            label="Risk Score"
                            value={
                              <strong className="risk-value">
                                {riskScore} / 100
                              </strong>
                            }
                          />

                          <SummaryRow
                            icon="♢"
                            label="Total Vulnerabilities"
                            value={total}
                          />

                          <SummaryRow
                            icon="▣"
                            label="Secrets Detected"
                            value={secrets.length}
                          />

                          <SummaryRow
                            icon="◇"
                            label="SBOM Components"
                            value={sbom.length}
                          />

                        </div>

                        <div className="risk-display">

                          <div
                            className="risk-circle"
                            style={{
                              '--risk':
                                `${Math.min(riskScore, 100) * 3.6}deg`,
                            }}
                          >
                            <div>
                              <strong>{riskScore}</strong>
                              <span>RISK SCORE</span>
                            </div>
                          </div>

                          <div
                            className={`risk-badge ${
                              riskScore >= 70
                                ? 'high-risk'
                                : 'low-risk'
                            }`}
                          >
                            {riskText(riskScore)}
                          </div>

                          <p>
                            {riskScore >= 70
                              ? 'Multiple security issues found in this image.'
                              : 'Image security posture looks good.'}
                          </p>

                        </div>

                        <button
                          className="download-report"
                          onClick={() =>
                            window.open(
                              `${API_BASE}/scan/${scan.id}/report`,
                              '_blank'
                            )
                          }
                        >
                          ↓ &nbsp; Download PDF Report
                        </button>

                      </div>

                    </section>

                    {/* ================= TABS ================= */}

                    <section className="results-panel">

                      <div className="result-tabs">

                        <div className="tab active">
                          Vulnerabilities
                        </div>

                        <div className="tab">
                          Exposed Secrets
                          <span>
                            {secrets.length}
                          </span>
                        </div>

                        <div className="tab">
                          SBOM Components
                          <span>
                            {sbom.length}
                          </span>
                        </div>

                      </div>

                      {/* VULNERABILITIES */}

                      <div className="table-heading">
                        <div>
                          <h2>Vulnerabilities</h2>
                          <p>
                            Security vulnerabilities detected
                            in the Docker image.
                          </p>
                        </div>

                        <div className="count-badge">
                          {total} Findings
                        </div>
                      </div>

                      {vulnerabilities.length === 0 ? (
                        <div className="success-message">
                          ✓ No vulnerabilities detected
                        </div>
                      ) : (
                        <div className="table-scroll">

                          <table>

                            <thead>
                              <tr>
                                <th>CVE ID</th>
                                <th>Package</th>
                                <th>Installed Version</th>
                                <th>Fixed Version</th>
                                <th>Severity</th>
                                <th>Source Tool</th>
                                <th>Description</th>
                              </tr>
                            </thead>

                            <tbody>

                              {vulnerabilities
                                .slice(0, 50)
                                .map((v, i) => (

                                  <tr key={i}>

                                    <td className="cve">
                                      {v.cve_id || '-'}
                                    </td>

                                    <td>
                                      {v.package || '-'}
                                    </td>

                                    <td>
                                      {v.installed_version || '-'}
                                    </td>

                                    <td>
                                      {v.fixed_version || '-'}
                                    </td>

                                    <td>
                                      <span
                                        className={`severity sev-${
                                          v.severity ||
                                          'UNKNOWN'
                                        }`}
                                      >
                                        {v.severity ||
                                          'UNKNOWN'}
                                      </span>
                                    </td>

                                    <td>
                                      {v.source_tool || '-'}
                                    </td>

                                    <td className="description">
                                      {v.description ||
                                        'Security vulnerability detected'}
                                    </td>

                                  </tr>

                                ))}

                            </tbody>

                          </table>

                        </div>
                      )}

                    </section>

                    {/* ================= SECRETS ================= */}

                    <section className="results-panel">

                      <div className="table-heading">

                        <div>
                          <h2>🔑 Exposed Secrets</h2>
                          <p>
                            Potential secrets detected inside
                            the image.
                          </p>
                        </div>

                        <div className="count-badge">
                          {secrets.length}
                        </div>

                      </div>

                      {secrets.length === 0 ? (
                        <div className="success-message">
                          ✓ No exposed secrets detected
                        </div>
                      ) : (
                        <div className="table-scroll">

                          <table>

                            <thead>
                              <tr>
                                <th>File</th>
                                <th>Rule</th>
                                <th>Match</th>
                              </tr>
                            </thead>

                            <tbody>

                              {secrets.map((s, i) => (

                                <tr key={i}>

                                  <td>
                                    {s.file_path || '-'}
                                  </td>

                                  <td>
                                    {s.rule_id || '-'}
                                  </td>

                                  <td className="secret-match">
                                    {s.match_snippet || '-'}
                                  </td>

                                </tr>

                              ))}

                            </tbody>

                          </table>

                        </div>
                      )}

                    </section>

                    {/* ================= SBOM ================= */}

                    <section className="results-panel">

                      <div className="table-heading">

                        <div>
                          <h2>📦 SBOM Components</h2>
                          <p>
                            Software components discovered
                            in the Docker image.
                          </p>
                        </div>

                        <div className="count-badge">
                          {sbom.length}
                        </div>

                      </div>

                      {sbom.length === 0 ? (
                        <div className="no-data">
                          No SBOM components available
                        </div>
                      ) : (
                        <div className="table-scroll">

                          <table>

                            <thead>
                              <tr>
                                <th>Component</th>
                                <th>Version</th>
                                <th>Type</th>
                              </tr>
                            </thead>

                            <tbody>

                              {sbom
                                .slice(0, 50)
                                .map((c, i) => (

                                  <tr key={i}>

                                    <td>
                                      {c.component_name || '-'}
                                    </td>

                                    <td>
                                      {c.version || '-'}
                                    </td>

                                    <td>
                                      {c.component_type || '-'}
                                    </td>

                                  </tr>

                                ))}

                            </tbody>

                          </table>

                        </div>
                      )}

                    </section>

                  </>
                )}

              </>
            )}
          </>
        )}

        {activeTab === 'scanner' && (
          <section className="ready-card">
            <div className="ready-icon">⌕</div>
            <h3>Image Scanner</h3>
            <p>Use the scan form on the Dashboard to start a new scan.</p>
            <button
              className="download-report"
              style={{ maxWidth: 220, margin: '16px auto 0' }}
              onClick={goToScanner}
            >
              Go to Scan Form
            </button>
          </section>
        )}

        {activeTab === 'vulns' && (
          <section className="results-panel">
            <div className="table-heading">
              <div>
                <h2>Vulnerabilities</h2>
                <p>All vulnerabilities from your most recent scan.</p>
              </div>
              <div className="count-badge">{total} Findings</div>
            </div>

            {!scan ? (
              <div className="no-data">Run a scan from the Dashboard first.</div>
            ) : vulnerabilities.length === 0 ? (
              <div className="success-message">✓ No vulnerabilities detected</div>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>CVE ID</th>
                      <th>Package</th>
                      <th>Severity</th>
                      <th>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vulnerabilities.slice(0, 50).map((v, i) => (
                      <tr key={i}>
                        <td className="cve">{v.cve_id || '-'}</td>
                        <td>{v.package || '-'}</td>
                        <td>
                          <span className={`severity sev-${v.severity || 'UNKNOWN'}`}>
                            {v.severity || 'UNKNOWN'}
                          </span>
                        </td>
                        <td className="description">{v.description || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        {activeTab === 'sbom' && (
          <section className="results-panel">
            <div className="table-heading">
              <div>
                <h2>📦 SBOM Components</h2>
                <p>Software components from your most recent scan.</p>
              </div>
              <div className="count-badge">{sbom.length}</div>
            </div>

            {!scan ? (
              <div className="no-data">Run a scan from the Dashboard first.</div>
            ) : sbom.length === 0 ? (
              <div className="no-data">No SBOM components available</div>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Component</th>
                      <th>Version</th>
                      <th>Type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sbom.slice(0, 50).map((c, i) => (
                      <tr key={i}>
                        <td>{c.component_name || '-'}</td>
                        <td>{c.version || '-'}</td>
                        <td>{c.component_type || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        {activeTab === 'history' && (
          <section className="ready-card">
            <div className="ready-icon">◷</div>
            <h3>Scan History</h3>
            <p>Hook this up to a GET /api/scans endpoint to list past scans here.</p>
          </section>
        )}

        {activeTab === 'settings' && (
          <section className="ready-card">
            <div className="ready-icon">⚙</div>
            <h3>Settings</h3>
            <p>Nothing configurable yet — add your app settings here.</p>
          </section>
        )}

        <footer>
          ContainerShield AI • Docker Security Platform
        </footer>

      </main>

    </div>
  )
}


/* ================= SMALL COMPONENTS ================= */

function StatCard({
  icon,
  title,
  value,
  type,
}) {
  return (
    <div className={`stat-card ${type}`}>

      <div className="stat-icon">
        {icon}
      </div>

      <div>
        <div className="stat-title">
          {title}
        </div>

        <div className="stat-value">
          {value}
        </div>

        <div className="stat-subtitle">
          Security findings
        </div>
      </div>

    </div>
  )
}


function SummaryRow({
  icon,
  label,
  value,
}) {
  return (
    <div className="summary-row">

      <span className="summary-icon">
        {icon}
      </span>

      <span className="summary-label">
        {label}
      </span>

      <span className="summary-value">
        {value}
      </span>

    </div>
  )
}