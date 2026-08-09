"""
scanner.py
Wraps the CLI security tools (Trivy, Grype, Gitleaks, Syft) and normalizes
their output into a common shape the rest of the app can use.

Each tool must already be installed and on PATH:
  - trivy    https://aquasecurity.github.io/trivy/
  - grype    https://github.com/anchore/grype
  - gitleaks https://github.com/gitleaks/gitleaks
  - syft     https://github.com/anchore/syft
"""
import json
import subprocess
import tempfile
import os


class ToolNotFoundError(Exception):
    pass


def _run(cmd: list[str], timeout: int = 300) -> str:
    """Run a CLI command and return stdout. Raises on non-zero exit
    (Trivy/Grype can return non-zero when vulns are found, so we only
    treat it as an error if stdout is empty and stderr has content)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError as e:
        raise ToolNotFoundError(f"Tool not found: {cmd[0]}") from e

    if not result.stdout.strip() and result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\nstderr: {result.stderr[:2000]}"
        )
    return result.stdout


def run_trivy(image_name: str) -> dict:
    """Vulnerability scan via Trivy. Returns parsed JSON."""
    out = _run(["trivy", "image", "--format", "json", "--quiet", image_name])
    return json.loads(out) if out.strip() else {}


def run_grype(image_name: str) -> dict:
    """Cross-check vulnerability scan via Grype. Returns parsed JSON."""
    out = _run(["grype", image_name, "-o", "json", "-q"])
    return json.loads(out) if out.strip() else {}


def run_syft(image_name: str) -> dict:
    """SBOM generation via Syft. Returns parsed JSON (CycloneDX-ish)."""
    out = _run(["syft", image_name, "-o", "json", "-q"])
    return json.loads(out) if out.strip() else {}


def run_gitleaks(image_name: str) -> dict:
    """
    Secret scanning. Gitleaks scans a filesystem, not an image directly,
    so we export the image's filesystem first via `docker export`.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        container_name = f"cs-tmp-{os.getpid()}"
        try:
            subprocess.run(
                ["docker", "create", "--name", container_name, image_name],
                check=True, capture_output=True, text=True, timeout=120,
            )
            tar_path = os.path.join(tmpdir, "fs.tar")
            with open(tar_path, "wb") as f:
                export = subprocess.run(
                    ["docker", "export", container_name],
                    stdout=f, timeout=180,
                )
            extract_dir = os.path.join(tmpdir, "fs")
            os.makedirs(extract_dir, exist_ok=True)
            subprocess.run(
                ["tar", "-xf", tar_path, "-C", extract_dir],
                check=False, capture_output=True, timeout=180,
            )
            report_path = os.path.join(tmpdir, "gitleaks-report.json")
            subprocess.run(
                [
                    "gitleaks", "detect",
                    "--source", extract_dir,
                    "--no-git",
                    "--report-format", "json",
                    "--report-path", report_path,
                    "--exit-code", "0",
                ],
                capture_output=True, text=True, timeout=180,
            )
            if os.path.exists(report_path):
                with open(report_path) as f:
                    content = f.read().strip()
                    return json.loads(content) if content else []
            return []
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True, timeout=60,
            )


def normalize_trivy(trivy_json: dict) -> list[dict]:
    """Flatten Trivy JSON into a common vulnerability shape."""
    findings = []
    for result in trivy_json.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "cve_id": vuln.get("VulnerabilityID", "UNKNOWN"),
                "package": vuln.get("PkgName", "unknown"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
                "severity": (vuln.get("Severity") or "UNKNOWN").upper(),
                "source_tool": "trivy",
                "description": (vuln.get("Description") or "")[:1000],
            })
    return findings


def normalize_grype(grype_json: dict) -> list[dict]:
    """Flatten Grype JSON into a common vulnerability shape."""
    findings = []
    for match in grype_json.get("matches", []) or []:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        fixed_versions = vuln.get("fix", {}).get("versions", [])
        findings.append({
            "cve_id": vuln.get("id", "UNKNOWN"),
            "package": artifact.get("name", "unknown"),
            "installed_version": artifact.get("version"),
            "fixed_version": fixed_versions[0] if fixed_versions else None,
            "severity": (vuln.get("severity") or "UNKNOWN").upper(),
            "source_tool": "grype",
            "description": (vuln.get("description") or "")[:1000],
        })
    return findings


def normalize_gitleaks(gitleaks_findings: list) -> list[dict]:
    """Flatten Gitleaks findings into a common secret shape."""
    secrets = []
    for f in gitleaks_findings or []:
        secret_text = f.get("Secret", "")
        redacted = (secret_text[:4] + "..." + secret_text[-2:]) if len(secret_text) > 8 else "***"
        secrets.append({
            "file_path": f.get("File", "unknown"),
            "rule_id": f.get("RuleID", "unknown"),
            "match_snippet": redacted,
        })
    return secrets


def normalize_syft(syft_json: dict) -> list[dict]:
    """Flatten Syft JSON into a common SBOM component shape."""
    components = []
    for artifact in syft_json.get("artifacts", []) or []:
        components.append({
            "component_name": artifact.get("name", "unknown"),
            "version": artifact.get("version"),
            "component_type": artifact.get("type", "unknown"),
        })
    return components


def calculate_risk_score(vulnerabilities: list[dict]) -> float:
    """Simple weighted risk score out of 100 based on severity counts."""
    weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "UNKNOWN": 0.2}
    raw = sum(weights.get(v["severity"], 0.2) for v in vulnerabilities)
    return round(min(raw, 100.0), 2)


def deduplicate_vulnerabilities(vulns: list[dict]) -> list[dict]:
    """Merge Trivy + Grype results, keyed by (cve_id, package), keep first seen."""
    seen = {}
    for v in vulns:
        key = (v["cve_id"], v["package"])
        if key not in seen:
            seen[key] = v
    return list(seen.values())


def run_full_scan(image_name: str) -> dict:
    """
    Orchestrates all four tools and returns normalized results plus raw
    output (for the raw_output JSONB column / debugging).
    """
    raw = {}
    all_vulns = []

    trivy_raw = run_trivy(image_name)
    raw["trivy"] = trivy_raw
    all_vulns += normalize_trivy(trivy_raw)

    grype_raw = run_grype(image_name)
    raw["grype"] = grype_raw
    all_vulns += normalize_grype(grype_raw)

    vulnerabilities = deduplicate_vulnerabilities(all_vulns)

    gitleaks_raw = run_gitleaks(image_name)
    raw["gitleaks"] = gitleaks_raw
    secrets = normalize_gitleaks(gitleaks_raw)

    syft_raw = run_syft(image_name)
    raw["syft"] = syft_raw
    sbom = normalize_syft(syft_raw)

    risk_score = calculate_risk_score(vulnerabilities)

    return {
        "vulnerabilities": vulnerabilities,
        "secrets": secrets,
        "sbom_components": sbom,
        "risk_score": risk_score,
        "raw": raw,
    }
