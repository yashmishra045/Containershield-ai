
import './welcome.css'

function Welcome({ onGetStarted }) {
  return (
    <div className="welcome-page">
      <nav className="welcome-nav">
        <div className="welcome-logo">
          🛡️ ContainerShield <span>AI</span>
        </div>
        <button onClick={onGetStarted} className="nav-button">
          Login
        </button>
      </nav>

      <main className="welcome-content">
        <div className="welcome-badge">
          AI-POWERED CONTAINER SECURITY
        </div>

        <h1>
          Secure Your Containers.
          <span> Ship With Confidence.</span>
        </h1>

        <p>
          Scan container images, detect vulnerabilities,
          analyze security risks and protect your applications
          with ContainerShield AI.
        </p>

        <button
          className="get-started-button"
          onClick={onGetStarted}
        >
          Get Started <span>→</span>
        </button>

        <div className="welcome-features">
          <div>🛡️ Vulnerability Scanning</div>
          <div>🔍 Security Analysis</div>
          <div>📦 SBOM Generation</div>
        </div>
      </main>

      <footer className="welcome-footer">
        ContainerShield AI · Secure Your Container Ecosystem
      </footer>
    </div>
  )
}

export default Welcome
