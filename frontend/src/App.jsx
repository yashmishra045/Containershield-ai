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
  const [token, setToken] = useState(() => {
    try { return localStorage.getItem('csai-access-token') || '' } catch { return '' }
  })
  const [currentUser, setCurrentUser] = useState(null)
  const [authView, setAuthView] = useState(() => {
    try { return localStorage.getItem('csai-access-token') ? 'app' : 'login' } catch { return 'login' }
  })
  const [authError, setAuthError] = useState('')
  const [authLoading, setAuthLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [activeTab, setActiveTab] = useState('dashboard')
  const [adminUsers, setAdminUsers] = useState([])
  const [loginHistory, setLoginHistory] = useState([])
  const [adminLoading, setAdminLoading] = useState(false)
  const [adminError, setAdminError] = useState('')
  const [imageName, setImageName] = useState('nginx:latest')
  const [scan, setScan] = useState(null)
  const [dashboardStats, setDashboardStats] = useState({ total_scans: 0, last_scan: null })
  const [statsError, setStatsError] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('csai-theme') || 'dark' } catch { return 'dark' }
  })
  const pollRef = useRef(null)
  const activeScanIdRef = useRef(null)

  useEffect(() => {
    try { localStorage.setItem('csai-theme', theme) } catch { /* storage may be unavailable */ }
  }, [theme])

  useEffect(() => {
    return () => {
      if (pollRef.current) clearTimeout(pollRef.current)
      activeScanIdRef.current = null
    }
  }, [])

  async function apiFetch(path, options = {}) {
    const activeToken = token || (() => { try { return localStorage.getItem('csai-access-token') || '' } catch { return '' } })()
    const headers = new Headers(options.headers || {})
    if (activeToken) headers.set('Authorization', `Bearer ${activeToken}`)
    return fetch(`${API_BASE}${path}`, { ...options, headers })
  }

  async function refreshAdminData() {
    setAdminLoading(true)
    setAdminError('')
    try {
      const [usersRes, historyRes] = await Promise.all([
        apiFetch('/auth/admin/users', { cache: 'no-store' }),
        apiFetch('/auth/admin/login-history', { cache: 'no-store' }),
      ])

      if (!usersRes.ok) {
        const body = await usersRes.json().catch(() => ({}))
        throw new Error(body.detail || `Users request failed (${usersRes.status})`)
      }
      if (!historyRes.ok) {
        const body = await historyRes.json().catch(() => ({}))
        throw new Error(body.detail || `Login history request failed (${historyRes.status})`)
      }

      const [users, history] = await Promise.all([
        usersRes.json(),
        historyRes.json(),
      ])
      setAdminUsers(Array.isArray(users) ? users : [])
      setLoginHistory(Array.isArray(history) ? history : [])
    } catch (err) {
      setAdminError(err.message || 'Unable to load admin data')
    } finally {
      setAdminLoading(false)
    }
  }

  useEffect(() => {
    if (authView === 'app' && currentUser?.role === 'admin' && activeTab === 'admin') {
      refreshAdminData()
    }
  }, [authView, currentUser, activeTab])

  function formatAdminDate(value) {
    if (!value) return 'Never'
    const date = new Date(value)
    return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString()
  }

  async function refreshDashboardStats() {
    try {
      const res = await apiFetch('/dashboard/stats')
      if (!res.ok) {
        throw new Error(`Dashboard stats request failed (${res.status})`)
      }
      const data = await res.json()
      setDashboardStats({
        total_scans: Number(data.total_scans || 0),
        last_scan: data.last_scan || null,
      })
      setStatsError('')
    } catch (err) {
      setStatsError(err.message || 'Unable to load dashboard statistics')
    }
  }

  useEffect(() => {
    let cancelled = false
    async function restoreSession() {
      if (!token) { setAuthView('login'); return }
      try {
        const res = await apiFetch('/auth/me')
        if (!res.ok) throw new Error('Session expired')
        const user = await res.json()
        if (!cancelled) { setCurrentUser(user); setAuthView('app') }
      } catch {
        try { localStorage.removeItem('csai-access-token') } catch {}
        if (!cancelled) { setToken(''); setCurrentUser(null); setAuthView('login') }
      }
    }
    restoreSession()
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (authView === 'app' && token) refreshDashboardStats()
  }, [authView, token])

  async function startScan(e) {
    e.preventDefault()

    if (!imageName.trim()) {
      setError('Please enter a Docker image name')
      return
    }

    if (pollRef.current) clearTimeout(pollRef.current)
    activeScanIdRef.current = null

    setLoading(true)
    setError('')
    setScan(null)

    try {
      const res = await apiFetch('/scan', {
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

      if (!data?.id) {
        throw new Error("Scan API did not return a scan ID")
      }

      activeScanIdRef.current = String(data.id)
      setScan(data)
      refreshDashboardStats()
      pollStatus(data.id)
    } catch (err) {
      setError(err.message || 'Unable to start scan')
      setLoading(false)
    }
  }

  function pollStatus(id) {
    const scanId = String(id)

    if (pollRef.current) clearTimeout(pollRef.current)
    activeScanIdRef.current = scanId

    const scheduleNextPoll = () => {
      if (activeScanIdRef.current !== scanId) return

      pollRef.current = setTimeout(() => {
        fetchLatestStatus()
      }, 3000)
    }

    const fetchLatestStatus = async () => {
      if (activeScanIdRef.current !== scanId) return

      try {
        const res = await apiFetch(`/scan/${encodeURIComponent(scanId)}`, {
          cache: 'no-store',
        })

        if (!res.ok) {
          const message = `Scan status request failed (${res.status})`
          console.warn(message)

          // Retry transient API/proxy errors without starting overlapping requests.
          scheduleNextPoll()
          return
        }

        const data = await res.json()

        // Ignore responses belonging to an older scan.
        if (activeScanIdRef.current !== scanId || String(data?.id) !== scanId) {
          return
        }

        setScan(data)

        const status = String(data?.status || '').trim().toLowerCase()
        const isComplete = ['done', 'completed', 'complete', 'success', 'succeeded'].includes(status)
        const isFailed = ['failed', 'error', 'cancelled', 'canceled'].includes(status)

        if (isComplete || isFailed) {
          if (pollRef.current) clearTimeout(pollRef.current)
          pollRef.current = null
          activeScanIdRef.current = null
          setLoading(false)
          refreshDashboardStats()
          return
        }

        scheduleNextPoll()
      } catch (err) {
        console.error('Unable to fetch scan status:', err)
        scheduleNextPoll()
      }
    }

    // Fetch immediately, then continue with sequential 3-second polling.
    fetchLatestStatus()
  }

  const vulnerabilities = scan?.vulnerabilities || []
  const severityRank = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    UNKNOWN: 4,
  }
  const sortedVulnerabilities = [...vulnerabilities].sort((a, b) => {
    const severityA = String(a?.severity || 'UNKNOWN').toUpperCase()
    const severityB = String(b?.severity || 'UNKNOWN').toUpperCase()
    return (severityRank[severityA] ?? severityRank.UNKNOWN) -
      (severityRank[severityB] ?? severityRank.UNKNOWN)
  })
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

  function handleLogout() {
    if (pollRef.current) clearTimeout(pollRef.current)
    activeScanIdRef.current = null
    try { localStorage.removeItem('csai-access-token') } catch {}
    setToken('')
    setCurrentUser(null)
    setScan(null)
    setAuthError('')
    setAuthView('login')
  }

  async function downloadScanReport() {
    try {
      const res = await apiFetch(`/scan/${scan.id}/report`)
      if (!res.ok) throw new Error(`Report download failed (${res.status})`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `csai-scan-${scan.id}.pdf`
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
    } catch (err) { setError(err.message || 'Unable to download report') }
  }

  if (authView !== 'app') {
    const isSignup = authView === 'signup'
    const isForgot = authView === 'forgot'

    async function handleAuthSubmit(event) {
      event.preventDefault()
      setAuthError('')
      if (isForgot) {
        setAuthError('Password recovery is not available yet. Please contact your administrator.')
        return
      }
      const formData = new FormData(event.currentTarget)
      const payload = {
        email: String(formData.get('email') || '').trim(),
        password: String(formData.get('password') || ''),
      }
      if (isSignup) payload.full_name = String(formData.get('full_name') || '').trim()
      setAuthLoading(true)
      try {
        const res = await fetch(`${API_BASE}/auth/${isSignup ? 'signup' : 'login'}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        })
        const data = await res.json().catch(() => ({}))
        if (!res.ok) {
          const detail = data.detail
          throw new Error(Array.isArray(detail) ? detail.map(item => item.msg).join(', ') : detail || `Authentication failed (${res.status})`)
        }
        if (!data.access_token || !data.user) throw new Error('Authentication response is incomplete')
        try { localStorage.setItem('csai-access-token', data.access_token) } catch {}
        setToken(data.access_token)
        setCurrentUser(data.user)
        setAuthView('app')
        setAuthError('')
      } catch (err) {
        setAuthError(err.message || 'Unable to authenticate')
      } finally {
        setAuthLoading(false)
      }
    }

    return (
      <div className="auth-shell" data-theme={theme}>
        <div className="auth-glow auth-glow-one" />
        <div className="auth-glow auth-glow-two" />
        <header className="auth-brand">
          <div className="brand-shield">🛡</div>
          <div>
            <div className="brand-name">ContainerShield <span>AI</span></div>
            <div className="brand-sub">CONTAINER SECURITY PLATFORM</div>
          </div>
        </header>

        <main className="auth-layout">
          <section className="auth-promo">
            <div className="auth-eyebrow"><span className="online-dot" /> AI-POWERED CONTAINER SECURITY</div>
            <h1>Secure every image.<br /><span>Ship with confidence.</span></h1>
            <p>Find vulnerabilities, exposed secrets and software components before your containers reach production.</p>
            <div className="auth-feature-list">
              <div><span>✓</span><div><strong>Deep image scanning</strong><small>Trivy · Grype · Syft · Gitleaks</small></div></div>
              <div><span>✓</span><div><strong>Actionable security insights</strong><small>Prioritized findings and CVE intelligence</small></div></div>
              <div><span>✓</span><div><strong>Software bill of materials</strong><small>Know what is inside every image</small></div></div>
            </div>
            <div className="auth-promo-foot"><span className="auth-pulse" /> Your container security command center</div>
          </section>

          <section className="auth-card">
            <div className="auth-card-top">
              <div className="auth-card-icon">{isForgot ? '✉' : isSignup ? '＋' : '↗'}</div>
              <div className="auth-card-kicker">{isForgot ? 'ACCOUNT RECOVERY' : isSignup ? 'GET STARTED' : 'WELCOME BACK'}</div>
              <h2>{isForgot ? 'Reset your password' : isSignup ? 'Create your account' : 'Sign in to CSAI'}</h2>
              <p>{isForgot ? 'Enter your email and we’ll send you reset instructions.' : isSignup ? 'Create an account to manage your container security.' : 'Access your security dashboard and scan history.'}</p>
            </div>

            <form className="auth-form" onSubmit={handleAuthSubmit}>
              {isSignup && (
                <label className="auth-field">
                  <span>Full name</span>
                  <input name="full_name" type="text" placeholder="Enter your full name" autoComplete="name" minLength={2} maxLength={120} required />
                </label>
              )}
              <label className="auth-field">
                <span>Email address</span>
                <input name="email" type="email" placeholder="you@company.com" autoComplete="email" required />
              </label>
              {!isForgot && (
                <label className="auth-field">
                  <span>Password</span>
                  <div className="auth-password-wrap">
                    <input type={showPassword ? 'text' : 'password'} placeholder="Enter your password" name="password" autoComplete={isSignup ? 'new-password' : 'current-password'} minLength={isSignup ? 10 : 1} required />
                    <button type="button" className="auth-show-password" onClick={() => setShowPassword(value => !value)}>{showPassword ? 'Hide' : 'Show'}</button>
                  </div>
                </label>
              )}
              {authError && <div className="auth-inline-error" role="alert">{authError}</div>}
              <button className="auth-submit" type="submit" disabled={authLoading}>{authLoading ? 'Please wait...' : isForgot ? 'Send reset instructions' : isSignup ? 'Create account' : 'Sign in'} <span>→</span></button>
            </form>

            {!isForgot && !isSignup && (
              <div className="auth-forgot-row"><button type="button" onClick={() => { setAuthError(''); setAuthView('forgot') }}>Forgot password?</button></div>
            )}
            <div className="auth-switch">
              {isForgot ? <>Remembered your password? <button type="button" onClick={() => { setAuthError(''); setAuthView('login') }}>Back to sign in</button></>
                : isSignup ? <>Already have an account? <button type="button" onClick={() => { setAuthError(''); setAuthView('login') }}>Sign in</button></>
                : <>New to ContainerShield AI? <button type="button" onClick={() => { setAuthError(''); setAuthView('signup') }}>Create an account</button></>}
            </div>
            <div className="auth-card-foot"><span>🔒</span> Protected access for your security workspace</div>
          </section>
        </main>
        <footer className="auth-footer">© {new Date().getFullYear()} ContainerShield AI <span>•</span> Docker Security Platform</footer>
      </div>
    )
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
          {[...NAV_ITEMS, ...(currentUser?.role === 'admin' ? [{ key: 'admin', label: 'Admin Panel', icon: '♙' }] : [])].map((item) => (
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
            {currentUser?.full_name || currentUser?.email || 'Signed in'}
          </div>
          <button type="button" className="download-report" onClick={handleLogout}>Sign out</button>
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
                <div className="stat-block-num">
                  {dashboardStats.total_scans}
                </div>
                <div className="stat-block-lbl">Images Scanned</div>
                <div className="stat-block-sub">
                  {statsError ? 'Unable to refresh count' : 'Total scans in database'}
                </div>
              </div>

              <div className="stat-block">
                <div className="stat-block-num bad">
                  {counts.CRITICAL || 0}
                </div>
                <div className="stat-block-lbl">Critical Vulns</div>
                <div className="stat-block-sub">from current scan</div>
              </div>

              <div className="stat-block">
                <div className="stat-block-num">
                  {dashboardStats.last_scan?.image_name || '—'}
                </div>
                <div className="stat-block-lbl">Last Scanned Image</div>
                <div className="stat-block-sub">
                  {dashboardStats.last_scan
                    ? `${dashboardStats.last_scan.status || 'unknown'}${dashboardStats.last_scan.created_at
                      ? ` · ${new Date(dashboardStats.last_scan.created_at).toLocaleString()}`
                      : ''}`
                    : 'no scans yet'}
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
                      <strong>Overall Scan Progress</strong>
                      <p>Scanning <b>{imageName.trim()}</b>. Large images may take a few minutes.</p>
                    </div>
                  </div>

                  <div className="progress-meta">
                    <span>{scan?.current_stage || 'Preparing scan...'}</span>
                    <strong>{Math.min(100, Math.max(0, Number(scan?.progress ?? 0)))}%</strong>
                  </div>

                  <div
                    className="progress-track"
                    role="progressbar"
                    aria-label="Overall scan progress"
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={Math.min(100, Math.max(0, Number(scan?.progress ?? 0)))}
                  >
                    <span
                      className="progress-fill"
                      style={{
                        width: `${Math.min(100, Math.max(0, Number(scan?.progress ?? 0)))}%`
                      }}
                    />
                  </div>
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

                        <button className="download-report" onClick={downloadScanReport}>
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

                              {sortedVulnerabilities
                                .slice(0, 50)
                                .map((v, i) => (

                                  <tr key={i}>

                                    <td className="cve">
                                      {v.cve_id && /^CVE-\d{4}-\d+$/i.test(v.cve_id) ? (
                                        <a
                                          href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve_id)}`}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          title="View on NVD"
                                        >
                                          {v.cve_id}
                                        </a>
                                      ) : (
                                        v.cve_id || '-'
                                      )}
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
                    {sortedVulnerabilities.slice(0, 50).map((v, i) => (
                      <tr key={i}>
                        <td className="cve">
                          {v.cve_id && /^CVE-\d{4}-\d+$/i.test(v.cve_id) ? (
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve_id)}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              title="View on NVD"
                            >
                              {v.cve_id}
                            </a>
                          ) : (
                            v.cve_id || '-'
                          )}
                        </td>
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

        {activeTab === 'admin' && currentUser?.role === 'admin' && (
          <section className="admin-page">
            <div className="admin-page-heading">
              <div>
                <div className="small-label">ADMINISTRATION</div>
                <h1>User Management</h1>
                <p>Registered accounts, scan usage and successful sign-in activity.</p>
              </div>
              <button
                type="button"
                className="download-report"
                onClick={refreshAdminData}
                disabled={adminLoading}
              >
                {adminLoading ? 'Refreshing...' : '↻ Refresh'}
              </button>
            </div>

            {adminError && <div className="scan-error" role="alert">{adminError}</div>}

            <div className="admin-summary-grid">
              <div className="admin-summary-card">
                <span>Total users</span>
                <strong>{adminUsers.length}</strong>
              </div>
              <div className="admin-summary-card">
                <span>Administrators</span>
                <strong>{adminUsers.filter(user => user.role === 'admin').length}</strong>
              </div>
              <div className="admin-summary-card">
                <span>Regular users</span>
                <strong>{adminUsers.filter(user => user.role !== 'admin').length}</strong>
              </div>
              <div className="admin-summary-card">
                <span>Total scans</span>
                <strong>{adminUsers.reduce((sum, user) => sum + Number(user.scan_count || 0), 0)}</strong>
              </div>
            </div>

            <section className="panel admin-panel-section">
              <div className="panel-title">♙ Registered Users</div>
              {adminLoading && adminUsers.length === 0 ? (
                <div className="no-data">Loading users...</div>
              ) : adminUsers.length === 0 ? (
                <div className="no-data">No users found.</div>
              ) : (
                <div className="table-scroll">
                  <table className="admin-table">
                    <thead>
                      <tr>
                        <th>User</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Scans</th>
                        <th>Joined</th>
                        <th>Last login</th>
                      </tr>
                    </thead>
                    <tbody>
                      {adminUsers.map(user => (
                        <tr key={user.id}>
                          <td>{user.full_name}</td>
                          <td>{user.email}</td>
                          <td><span className={`admin-role ${user.role === 'admin' ? 'is-admin' : ''}`}>{user.role}</span></td>
                          <td>{user.is_active ? 'Active' : 'Disabled'}</td>
                          <td>{Number(user.scan_count || 0)}</td>
                          <td>{formatAdminDate(user.created_at)}</td>
                          <td>{formatAdminDate(user.last_login_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <section className="panel admin-panel-section">
              <div className="panel-title">◷ Recent Successful Logins</div>
              {loginHistory.length === 0 ? (
                <div className="no-data">
                  No login events yet. New successful logins will appear here.
                </div>
              ) : (
                <div className="table-scroll">
                  <table className="admin-table">
                    <thead>
                      <tr><th>User</th><th>Email</th><th>Login time</th></tr>
                    </thead>
                    <tbody>
                      {loginHistory.map((entry, index) => (
                        <tr key={`${entry.email}-${entry.logged_in_at}-${index}`}>
                          <td>{entry.full_name}</td>
                          <td>{entry.email}</td>
                          <td>{formatAdminDate(entry.logged_in_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
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