import traceback

import uuid

from datetime import datetime

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException

from fastapi.middleware.cors import CORSMiddleware

from fastapi.responses import Response, StreamingResponse

from sqlalchemy import func

from sqlalchemy.orm import Session

import csv

import io

import json

import re

from . import models, report, scanner, schemas

from .database import Base, engine, get_db

from .auth import router as auth_router, get_current_user

# Create tables (development use). create_all does NOT add columns to existing tables;

# run the supplied SQL migration once against an existing database.

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ContainerShield AI", version="0.3.0")

app.include_router(auth_router)

app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

)

def sanitize_for_postgres(value):

    """Recursively remove actual and JSON-escaped NUL characters."""

    if isinstance(value, str):

        value = value.replace("\x00", "")

        return re.sub(r"(?i)\\+u0000", "", value)

    if isinstance(value, dict):

        return {

            sanitize_for_postgres(key): sanitize_for_postgres(item)

            for key, item in value.items()

        }

    if isinstance(value, list):

        return [sanitize_for_postgres(item) for item in value]

    if isinstance(value, tuple):

        return tuple(sanitize_for_postgres(item) for item in value)

    return value

def redact_gitleaks_raw(raw_output):

    """Remove secret-bearing Gitleaks fields while preserving finding metadata."""

    sensitive_keys = {"match", "secret"}

    def redact(value):

        if isinstance(value, dict):

            return {

                key: redact(item)

                for key, item in value.items()

                if str(key).lower() not in sensitive_keys

            }

        if isinstance(value, list):

            return [redact(item) for item in value]

        if isinstance(value, tuple):

            return tuple(redact(item) for item in value)

        return value

    return redact(raw_output)

def _secret_fields(secret):

    """Map scanner output to DB fields; never persist raw secret values."""

    return {

        "file_path": sanitize_for_postgres(secret.get("file", "") or ""),

        "rule_id": sanitize_for_postgres(secret.get("rule_id", "") or ""),

        "match_snippet": sanitize_for_postgres(

            (secret.get("description") or "")[:200]

        ),

    }

def _sbom_fields(component):

    """Map scanner output to SBOMComponent model fields."""

    return {

        "component_name": sanitize_for_postgres(

            component.get("name", "unknown") or "unknown"

        ),

        "version": sanitize_for_postgres(component.get("version", "") or ""),

        "component_type": sanitize_for_postgres(component.get("type", "") or ""),

    }

def _execute_scan(scan_id: uuid.UUID):

    """Run scanners in the background and persist progress and results."""

    db_generator = get_db()

    db = None

    try:

        db = next(db_generator)

        scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()

        if scan is None:

            print(f"[SCAN] Scan not found: {scan_id}", flush=True)

            return

        scan.status = "running"

        scan.progress = 0

        scan.current_stage = "Starting scan"

        scan.error_message = None

        db.commit()

        image_name = scan.image_name

        print(f"[SCAN] Started: {scan_id} | Image: {image_name}", flush=True)

        def update_progress(percent: int, stage: str):

            """Persist overall pipeline progress without losing scan results on DB errors."""

            safe_percent = max(0, min(100, int(percent)))

            try:

                progress_scan = (

                    db.query(models.Scan)

                    .filter(models.Scan.id == scan_id)

                    .first()

                )

                if progress_scan is None:

                    return

                progress_scan.progress = safe_percent

                progress_scan.current_stage = sanitize_for_postgres(str(stage)[:120])

                db.commit()

                print(

                    f"[SCAN PROGRESS] {scan_id}: {safe_percent}% - {stage}",

                    flush=True,

                )

            except Exception as progress_error:

                db.rollback()

                print(

                    f"[PROGRESS WARNING] Could not persist progress: {progress_error}",

                    flush=True,

                )

        result = scanner.run_full_scan(

            image_name,

            progress_callback=update_progress,

        )

        # Persist vulnerabilities. Keep only fields present in the DB model.

        allowed_vulnerability_fields = (

            {column.name for column in models.Vulnerability.__table__.columns}

            - {"id", "scan_id"}

        )

        for item in result.get("vulnerabilities", []):

            vulnerability = item.copy()

            if "source" in vulnerability:

                source = vulnerability.pop("source")

                vulnerability.setdefault("source_tool", source)

            vulnerability = {

                key: sanitize_for_postgres(value)

                for key, value in vulnerability.items()

                if key in allowed_vulnerability_fields

            }

            # Ensure CVE IDs are normalized as text; the frontend can link them to NVD.

            if vulnerability.get("cve_id"):

                vulnerability["cve_id"] = str(vulnerability["cve_id"]).replace(

                    "\x00", ""

                )

            db.add(models.Vulnerability(scan_id=scan_id, **vulnerability))

        for secret in result.get("secrets", []):

            db.add(models.Secret(scan_id=scan_id, **_secret_fields(secret)))

        for component in result.get("sbom_components", []):

            db.add(

                models.SBOMComponent(

                    scan_id=scan_id,

                    **_sbom_fields(component),

                )

            )

        scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()

        if scan is None:

            raise RuntimeError(f"Scan record disappeared: {scan_id}")

        scan.risk_score = result.get("risk_score", 0) or 0

        # Do not persist raw scanner output. It can contain NUL bytes and

        # sensitive secret material (for example private-key contents).

        # Normalized vulnerability, secret metadata, and SBOM records are

        # persisted in their dedicated tables above.

        scan.raw_output = {

            "note": "Raw scanner output omitted; normalized findings are stored separately."

        }

        scan.status = "done"

        scan.progress = 100

        scan.current_stage = "Scan completed"

        scan.completed_at = datetime.utcnow()

        scanner_errors = sanitize_for_postgres(

            (result.get("raw") or {}).get("errors") or []

        )

        scan.error_message = (

            ("Partial scan: " + "; ".join(str(error) for error in scanner_errors))[:2000]

            if scanner_errors

            else None

        )

        db.commit()

        print(f"[SCAN] Completed: {scan_id}", flush=True)

    except Exception as exc:

        if db is not None:

            try:

                db.rollback()

                failed_scan = (

                    db.query(models.Scan)

                    .filter(models.Scan.id == scan_id)

                    .first()

                )

                if failed_scan is not None:

                    failed_scan.status = "failed"

                    failed_scan.current_stage = "Scan failed"

                    failed_scan.error_message = (

                        sanitize_for_postgres(f"{type(exc).__name__}: {exc}")

                    )[:2000].replace("\x00", "")

                    failed_scan.completed_at = datetime.utcnow()

                    db.commit()

            except Exception:

                db.rollback()

                traceback.print_exc()

        print(

            f"[SCAN ERROR] {scan_id}: {type(exc).__name__}: {exc}",

            flush=True,

        )

        traceback.print_exc()

    finally:

        if db is not None:

            db.close()

        try:

            db_generator.close()

        except Exception:

            traceback.print_exc()

@app.get("/health")

def health():

    return {"status": "ok"}

@app.post("/scan", response_model=schemas.ScanStatusOut)

def create_scan(

    req: schemas.ScanRequest,

    background_tasks: BackgroundTasks,

    db: Session = Depends(get_db),

    current_user: models.User = Depends(get_current_user),

):

    image_name = req.image_name.strip()

    if not image_name:

        raise HTTPException(status_code=422, detail="Image name cannot be empty")

    scan = models.Scan(

        image_name=image_name,

        user_id=current_user.id,

        status="pending",

        progress=0,

        current_stage="Queued",

    )

    db.add(scan)

    db.commit()

    db.refresh(scan)

    background_tasks.add_task(_execute_scan, scan.id)

    return scan

@app.get("/scan/{scan_id}", response_model=schemas.ScanDetailOut)

def get_scan(scan_id: uuid.UUID, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):

    scan = db.query(models.Scan).filter(models.Scan.id == scan_id, models.Scan.user_id == current_user.id).first()

    if scan is None:

        raise HTTPException(status_code=404, detail="Scan not found")

    return scan

@app.get("/scans", response_model=list[schemas.ScanStatusOut])

def list_scans(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):

    return (

        db.query(models.Scan).filter(models.Scan.user_id == current_user.id)

        .order_by(models.Scan.created_at.desc())

        .limit(50)

        .all()

    )

@app.get("/dashboard/stats")

def dashboard_stats(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):

    total_scans = db.query(func.count(models.Scan.id)).filter(models.Scan.user_id == current_user.id).scalar() or 0

    latest_scan = (

        db.query(models.Scan).filter(models.Scan.user_id == current_user.id)

        .order_by(models.Scan.created_at.desc())

        .first()

    )

    return {

        "total_scans": total_scans,

        "last_scan": (

            {

                "image_name": latest_scan.image_name,

                "status": latest_scan.status,

                "progress": latest_scan.progress,

                "current_stage": latest_scan.current_stage,

                "created_at": latest_scan.created_at,

            }

            if latest_scan is not None

            else None

        ),

    }

@app.get("/scan/{scan_id}/report")

def download_report(scan_id: uuid.UUID, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):

    scan = db.query(models.Scan).filter(models.Scan.id == scan_id, models.Scan.user_id == current_user.id).first()

    if scan is None:

        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "done":

        raise HTTPException(

            status_code=400,

            detail=f"Scan is not complete (status: {scan.status})",

        )

    pdf_bytes = report.generate_pdf_report(

        scan,

        scan.vulnerabilities,

        scan.secrets,

        scan.sbom_components,

    )

    filename = f"containershield-report-{scan.id}.pdf"

    return Response(

        content=pdf_bytes,

        media_type="application/pdf",

        headers={"Content-Disposition": f"attachment; filename={filename}"},

    )

@app.get("/scan/{scan_id}/sbom.csv")

def download_sbom_csv(scan_id: uuid.UUID, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):

    """Export SBOM inventory with vulnerability severity joined by package identity."""

    scan = db.query(models.Scan).filter(models.Scan.id == scan_id, models.Scan.user_id == current_user.id).first()

    if scan is None:

        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "done":

        raise HTTPException(

            status_code=400,

            detail=f"Scan is not complete (status: {scan.status})",

        )

    # Severity belongs to vulnerability findings, not to the SBOM inventory row.

    # Export findings separately in this CSV so package inventory is not mislabelled.

    output = io.StringIO(newline="")

    writer = csv.writer(output)

    writer.writerow([

        "Record Type",

        "Component / Package",

        "Version",

        "Component Type",

        "CVE ID",

        "Severity",

        "Fixed Version",

        "Source Tool",

        "NVD URL",

    ])

    rank = {

        "CRITICAL": 0,

        "HIGH": 1,

        "MEDIUM": 2,

        "LOW": 3,

        "NEGLIGIBLE": 4,

        "UNKNOWN": 5,

    }

    for component in scan.sbom_components:

        writer.writerow([

            "SBOM_COMPONENT",

            component.component_name or "",

            component.version or "",

            component.component_type or "",

            "",

            "",

            "",

            "",

            "",

        ])

    findings = sorted(

        scan.vulnerabilities,

        key=lambda item: (

            rank.get((item.severity or "UNKNOWN").upper(), 5),

            (item.cve_id or "").upper(),

        ),

    )

    for finding in findings:

        cve_id = (finding.cve_id or "").strip()

        nvd_url = (

            f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            if cve_id.upper().startswith("CVE-")

            else ""

        )

        writer.writerow([

            "VULNERABILITY",

            finding.package or "",

            finding.installed_version or "",

            "",

            cve_id,

            (finding.severity or "UNKNOWN").upper(),

            finding.fixed_version or "",

            finding.source_tool or "",

            nvd_url,

        ])

    csv_bytes = ("\ufeff" + output.getvalue()).encode("utf-8")

    filename = f"containershield-sbom-{scan.id}.csv"

    return Response(

        content=csv_bytes,

        media_type="text/csv; charset=utf-8",

        headers={"Content-Disposition": f'attachment; filename="{filename}"'},

    )
