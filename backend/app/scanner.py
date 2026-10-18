"""ContainerShield AI scanner wrapper for Trivy, Grype, Gitleaks and Syft."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import tarfile
from typing import Any


def _run(command: list[str], timeout: int = 600) -> tuple[str, str, int]:
    print(f"[RUN] {' '.join(command)}")

    p = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        shell=False,
    )

    out, err = p.stdout or "", p.stderr or ""

    if p.returncode != 0:
        raise RuntimeError(
            f"exit code {p.returncode}: "
            f"{(err.strip() or out.strip())[:1000]}"
        )

    return out, err, p.returncode


def _json(text: str, tool: str) -> Any:
    if not (text or "").strip():
        return {}

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"{tool} returned invalid JSON: {e}"
        ) from e


def _v(
    obj: dict[str, Any],
    *keys: str,
    default: Any = None,
) -> Any:
    for k in keys:
        x = obj.get(k)

        if x is not None and x != "":
            return x

    return default


def _sev(x: Any) -> str:
    x = str(x or "UNKNOWN").upper()

    return (
        x
        if x in {
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNKNOWN",
            "NEGLIGIBLE",
        }
        else "UNKNOWN"
    )


# ---------------- TRIVY ----------------

def run_trivy(image_name: str) -> dict[str, Any]:
    out, _, _ = _run(
        [
            "trivy",
            "image",
            "--format",
            "json",
            "--quiet",
            image_name,
        ]
    )

    data = _json(out, "Trivy")

    return data if isinstance(data, dict) else []


def normalize_trivy(
    data: dict[str, Any],
) -> list[dict[str, Any]]:

    result = []

    for target in data.get("Results", []) or []:

        if not isinstance(target, dict):
            continue

        for x in target.get("Vulnerabilities", []) or []:

            if not isinstance(x, dict):
                continue

            vid = _v(
                x,
                "VulnerabilityID",
                "id",
                default="UNKNOWN",
            )

            result.append(
                {
                    "id": vid,
                    "cve_id": vid,
                    "package": _v(
                        x,
                        "PkgName",
                        "PackageName",
                        default="unknown",
                    ),
                    "installed_version": _v(
                        x,
                        "InstalledVersion",
                        "Version",
                        default="",
                    ),
                    "fixed_version": _v(
                        x,
                        "FixedVersion",
                        default="",
                    ),
                    "severity": _sev(
                        x.get("Severity")
                    ),
                    "source_tool": "trivy",
                    "source": "trivy",
                    "target": target.get(
                        "Target",
                        "",
                    ),
                    "title": _v(
                        x,
                        "Title",
                        default="",
                    ),
                    "description": _v(
                        x,
                        "Description",
                        default="",
                    ),
                    "references": x.get(
                        "References",
                        [],
                    )
                    or [],
                    "primary_url": _v(
                        x,
                        "PrimaryURL",
                        default="",
                    ),
                }
            )

    return result


# ---------------- GRYPE ----------------

def run_grype(image_name: str) -> dict[str, Any]:
    out, _, _ = _run(
        [
            "grype",
            image_name,
            "-o",
            "json",
            "--quiet",
        ]
    )

    data = _json(out, "Grype")

    return data if isinstance(data, dict) else {}


def normalize_grype(
    data: dict[str, Any],
) -> list[dict[str, Any]]:

    result = []

    for match in data.get("matches", []) or []:

        if not isinstance(match, dict):
            continue

        vuln = match.get("vulnerability") or {}
        art = match.get("artifact") or {}

        fix = vuln.get("fix") or {}
        versions = fix.get("versions") or []

        fixed = (
            versions[0]
            if isinstance(versions, list) and versions
            else ""
        )

        vid = _v(
            vuln,
            "id",
            "ID",
            default="UNKNOWN",
        )

        result.append(
            {
                "id": vid,
                "cve_id": vid,
                "package": _v(
                    art,
                    "name",
                    "Name",
                    default="unknown",
                ),
                "installed_version": _v(
                    art,
                    "version",
                    "Version",
                    default="",
                ),
                "fixed_version": fixed,
                "severity": _sev(
                    _v(
                        vuln,
                        "severity",
                        "Severity",
                        default="UNKNOWN",
                    )
                ),
                "source_tool": "grype",
                "source": "grype",
                "target": art.get(
                    "locations",
                    [],
                )
                or [],
                "title": _v(
                    vuln,
                    "id",
                    default="",
                ),
                "description": _v(
                    vuln,
                    "description",
                    "Description",
                    default="",
                ),
                "references": [],
                "primary_url": "",
            }
        )

    return result


# ---------------- GITLEAKS ----------------

def run_gitleaks(
    image_name: str,
) -> list[dict[str, Any]]:
    """
    Scan a Docker image filesystem with Gitleaks.

    The Docker image is exported to a temporary directory first.
    Symlinks and hardlinks are deliberately skipped during extraction
    because Docker images commonly contain links such as
    /etc/alternatives/awk. Gitleaks can fail on those links when they
    point to absolute paths outside the extracted filesystem.
    """

    container_id = None

    try:
        print(f"[GITLEAKS] Starting scan for image: {image_name}")

        # 1. Create a temporary container from the image.
        create = subprocess.run(
            ["docker", "create", image_name],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            shell=False,
        )

        if create.returncode != 0:
            raise RuntimeError(
                f"Docker create failed: "
                f"{(create.stderr or create.stdout).strip()[:1000]}"
            )

        container_id = create.stdout.strip()

        if not container_id:
            raise RuntimeError("Docker did not return a container ID")

        print(f"[GITLEAKS] Temporary container: {container_id[:12]}")

        # 2. Work inside a temporary directory.
        with tempfile.TemporaryDirectory(
            prefix="containershield-gitleaks-"
        ) as temp_dir:

            tar_path = os.path.join(
                temp_dir,
                "filesystem.tar",
            )
            scan_dir = os.path.join(
                temp_dir,
                "filesystem",
            )
            report_path = os.path.join(
                temp_dir,
                "gitleaks-report.json",
            )

            os.makedirs(scan_dir, exist_ok=True)

            # 3. Export the image filesystem.
            print("[GITLEAKS] Exporting container filesystem...")

            with open(tar_path, "wb") as tar_file:
                export = subprocess.run(
                    ["docker", "export", container_id],
                    stdout=tar_file,
                    stderr=subprocess.PIPE,
                    timeout=300,
                    shell=False,
                )

            if export.returncode != 0:
                stderr = export.stderr.decode(
                    "utf-8",
                    errors="replace",
                ).strip()
                raise RuntimeError(
                    f"Docker export failed: {stderr[:1000]}"
                )

            # 4. Safely extract regular files and directories only.
            #    Do NOT use tar.extractall() here.
            print("[GITLEAKS] Extracting filesystem safely...")

            extracted = 0
            skipped_links = 0

            with tarfile.open(tar_path, "r") as archive:
                for member in archive:
                    name = member.name.replace("\\", "/")
                    name = name.lstrip("/")

                    if not name:
                        continue

                    normalized = os.path.normpath(name)

                    # Prevent path traversal.
                    if (
                        normalized == ".."
                        or normalized.startswith(".." + os.sep)
                        or os.path.isabs(normalized)
                    ):
                        continue

                    destination = os.path.join(
                        scan_dir,
                        normalized,
                    )

                    if member.isdir():
                        os.makedirs(destination, exist_ok=True)
                        continue

                    # Docker images commonly contain symlinks/hardlinks.
                    # Skip them rather than recreating unsafe links.
                    if member.issym() or member.islnk():
                        skipped_links += 1
                        continue

                    # Only extract normal files.
                    if not member.isfile():
                        continue

                    parent = os.path.dirname(destination)
                    os.makedirs(parent, exist_ok=True)

                    source = archive.extractfile(member)
                    if source is None:
                        continue

                    with source, open(destination, "wb") as output:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            output.write(chunk)

                    extracted += 1

            print(
                f"[GITLEAKS] Extracted {extracted} files; "
                f"skipped {skipped_links} links"
            )

            # 5. Run Gitleaks against the extracted filesystem.
            cmd = [
                "gitleaks",
                "dir",
                scan_dir,
                "--report-format",
                "json",
                "--report-path",
                report_path,
                "--no-banner",
                "--exit-code",
                "0",
            ]

            print(f"[RUN] {' '.join(cmd)}")

            scan = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=600,
                shell=False,
            )

            if scan.returncode != 0:
                raise RuntimeError(
                    f"Gitleaks failed with exit code "
                    f"{scan.returncode}: "
                    f"{(scan.stderr or scan.stdout).strip()[:1500]}"
                )

            # 6. Read the JSON report.
            if not os.path.exists(report_path):
                print("[GITLEAKS] No report generated; findings: 0")
                return []

            with open(
                report_path,
                "r",
                encoding="utf-8",
            ) as report_file:
                report_text = report_file.read().strip()

            if not report_text:
                return []

            data = _json(report_text, "Gitleaks")

            if isinstance(data, list):
                print(
                    f"[GITLEAKS] Scan completed. "
                    f"Findings: {len(data)}"
                )
                return data

            if isinstance(data, dict):
                return [data]

            return []

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Gitleaks scan timed out: {exc}"
        ) from exc

    finally:
        # 7. Always remove the temporary container.
        if container_id:
            try:
                subprocess.run(
                    ["docker", "rm", "-f", container_id],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=60,
                    shell=False,
                )
                print("[GITLEAKS] Temporary container removed")
            except Exception as cleanup_error:
                print(
                    f"[GITLEAKS] Cleanup warning: {cleanup_error}"
                )


def normalize_gitleaks(
    data: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    result = []

    for x in data or []:

        if not isinstance(x, dict):
            continue

        result.append(
            {
                "rule_id": _v(
                    x,
                    "RuleID",
                    "rule_id",
                    default="unknown",
                ),
                "description": _v(
                    x,
                    "Description",
                    "description",
                    default="Secret detected",
                ),
                "file": _v(
                    x,
                    "File",
                    "file",
                    default="",
                ),
                "line": _v(
                    x,
                    "StartLine",
                    "line",
                    default=0,
                ),
                "column": _v(
                    x,
                    "StartColumn",
                    "column",
                    default=0,
                ),
                "commit": _v(
                    x,
                    "Commit",
                    "commit",
                    default="",
                ),
                "author": _v(
                    x,
                    "Author",
                    "author",
                    default="",
                ),
                "email": _v(
                    x,
                    "Email",
                    "email",
                    default="",
                ),
                "date": _v(
                    x,
                    "Date",
                    "date",
                    default="",
                ),
                "source_tool": "gitleaks",
            }
        )

    return result


# ---------------- SYFT ----------------

def run_syft(
    image_name: str,
) -> list[dict[str, Any]]:

    out, _, _ = _run(
        [
            "syft",
            image_name,
            "-o",
            "json",
        ]
    )

    data = _json(out, "Syft")

    if isinstance(data, dict):
        return data.get(
            "artifacts",
            [],
        ) or []

    return (
        data
        if isinstance(data, list)
        else []
    )


def normalize_syft(
    data: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    result = []

    for x in data or []:

        if not isinstance(x, dict):
            continue

        result.append(
            {
                "name": _v(
                    x,
                    "name",
                    "Name",
                    default="unknown",
                ),
                "version": _v(
                    x,
                    "version",
                    "Version",
                    default="",
                ),
                "type": _v(
                    x,
                    "type",
                    "Type",
                    default="",
                ),
                "language": _v(
                    x,
                    "language",
                    "Language",
                    default="",
                ),
                "purl": _v(
                    x,
                    "purl",
                    "PURL",
                    default="",
                ),
                "locations": x.get(
                    "locations",
                    [],
                )
                or [],
                "source_tool": "syft",
            }
        )

    return result


# ---------------- MERGE / SCORE ----------------

def deduplicate_vulnerabilities(
    vulnerabilities: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    unique: dict[
        tuple[str, str, str],
        dict[str, Any],
    ] = {}

    rank = {
        "UNKNOWN": 0,
        "NEGLIGIBLE": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    for x in vulnerabilities:

        vid = str(
            x.get("id")
            or x.get("cve_id")
            or "UNKNOWN"
        )

        pkg = str(
            x.get("package")
            or "unknown"
        )

        ver = str(
            x.get("installed_version")
            or ""
        )

        key = (
            vid.upper(),
            pkg.lower(),
            ver,
        )

        if key not in unique:

            y = dict(x)

            y["source_tools"] = [
                x.get("source_tool")
                or x.get("source")
                or "unknown"
            ]

            unique[key] = y

        else:

            y = unique[key]

            tool = (
                x.get("source_tool")
                or x.get("source")
                or "unknown"
            )

            if tool not in y["source_tools"]:
                y["source_tools"].append(tool)

            if (
                not y.get("fixed_version")
                and x.get("fixed_version")
            ):
                y["fixed_version"] = (
                    x["fixed_version"]
                )

            if (
                not y.get("description")
                and x.get("description")
            ):
                y["description"] = (
                    x["description"]
                )

            if (
                rank.get(
                    _sev(x.get("severity")),
                    0,
                )
                >
                rank.get(
                    _sev(y.get("severity")),
                    0,
                )
            ):
                y["severity"] = _sev(
                    x.get("severity")
                )

    return list(unique.values())


def calculate_risk_score(
    vulnerabilities: list[dict[str, Any]],
) -> int:

    weights = {
        "CRITICAL": 10,
        "HIGH": 5,
        "MEDIUM": 2,
        "LOW": 1,
        "NEGLIGIBLE": 0,
        "UNKNOWN": 0,
    }

    return min(
        100,
        sum(
            weights.get(
                _sev(x.get("severity")),
                0,
            )
            for x in vulnerabilities
        ),
    )


# ---------------- FULL SCAN ----------------

def run_full_scan(
    image_name: str,
) -> dict[str, Any]:

    raw: dict[str, Any] = {}
    errors: list[str] = []
    all_vulns: list[dict[str, Any]] = []

    try:

        x = run_trivy(image_name)

        raw["trivy"] = x

        all_vulns += normalize_trivy(x)

        print("[OK] Trivy completed")

    except Exception as e:

        raw["trivy"] = {}

        errors.append(
            f"Trivy: {e}"
        )

        print(
            f"[ERROR] Trivy failed: {e}"
        )

    try:

        x = run_grype(image_name)

        raw["grype"] = x

        all_vulns += normalize_grype(x)

        print("[OK] Grype completed")

    except Exception as e:

        raw["grype"] = {}

        errors.append(
            f"Grype: {e}"
        )

        print(
            f"[ERROR] Grype failed: {e}"
        )

    vulnerabilities = deduplicate_vulnerabilities(
        all_vulns
    )

    try:

        x = run_gitleaks(image_name)

        raw["gitleaks"] = x

        secrets = normalize_gitleaks(x)

        print(
            "[OK] Gitleaks completed"
        )

    except Exception as e:

        raw["gitleaks"] = []

        secrets = []

        errors.append(
            f"Gitleaks: {e}"
        )

        print(
            f"[ERROR] Gitleaks failed: {e}"
        )

    try:

        x = run_syft(image_name)

        raw["syft"] = x

        sbom = normalize_syft(x)

        print(
            "[OK] Syft completed"
        )

    except Exception as e:

        raw["syft"] = []

        sbom = []

        errors.append(
            f"Syft: {e}"
        )

        print(
            f"[ERROR] Syft failed: {e}"
        )

    risk_score = calculate_risk_score(
        vulnerabilities
    )

    raw["errors"] = errors

    print(
        "===================================="
    )

    print(
        f"Scan completed: {image_name}"
    )

    print(
        f"Vulnerabilities: {len(vulnerabilities)}"
    )

    print(
        f"Secrets: {len(secrets)}"
    )

    print(
        f"SBOM components: {len(sbom)}"
    )

    print(
        f"Errors: {errors}"
    )

    print(
        "===================================="
    )

    return {
        "vulnerabilities": vulnerabilities,
        "secrets": secrets,
        "sbom_components": sbom,
        "risk_score": risk_score,
        "raw": raw,
    }