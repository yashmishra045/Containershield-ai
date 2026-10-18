
import uuid
import traceback
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy.orm import Session

from . import models, schemas, scanner, report
from .database import engine, get_db, Base


# Create tables (development use)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="ContainerShield AI", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _secret_fields(s):
    # Map scanner keys to Secret model columns (description is used, never the raw secret).
    return {
        "file_path": s.get("file", "") or "",
        "rule_id": s.get("rule_id", "") or "",
        "match_snippet": (s.get("description") or "")[:200],
    }


def _sbom_fields(c):
    # Map scanner keys to SBOMComponent model columns.
    return {
        "component_name": c.get("name", "unknown") or "unknown",
        "version": c.get("version", "") or "",
        "component_type": c.get("type", "") or "",
    }

def _execute_scan(scan_id: uuid.UUID):
    """Execute a scan and persist results."""

    db_generator = get_db()
    db = None

    try:
        db = next(db_generator)

        scan = (
            db.query(models.Scan)
            .filter(models.Scan.id == scan_id)
            .first()
        )

        if not scan:
            print(f"[SCAN] Scan not found: {scan_id}", flush=True)
            return

        scan.status = "running"
        scan.error_message = None
        db.commit()

        print(
            f"[SCAN] Started: {scan_id} | Image: {scan.image_name}",
            flush=True,
        )

        result = scanner.run_full_scan(scan.image_name)

        # Save vulnerabilities.
        for vulnerability in result.get("vulnerabilities", []):
            vulnerability = vulnerability.copy()

            # Scanner uses "source"; the SQLAlchemy model uses "source_tool".
            if "source" in vulnerability:
                source = vulnerability.pop("source")
                vulnerability.setdefault("source_tool", source)

            # Keep only keys that exist as columns in the Vulnerability model.
            allowed = {c.name for c in models.Vulnerability.__table__.columns} - {"id", "scan_id"}
            vulnerability = {k: v for k, v in vulnerability.items() if k in allowed}

            db.add(
                models.Vulnerability(
                    scan_id=scan.id,
                    **vulnerability,
                )
            )

        # Save detected secrets.
        for secret in result.get("secrets", []):
            db.add(
                models.Secret(
                    scan_id=scan.id,
                    **_secret_fields(secret),
                )
            )

        # Save SBOM components.
        for component in result.get("sbom_components", []):
            db.add(
                models.SBOMComponent(
                    scan_id=scan.id,
                    **_sbom_fields(component),
                )
            )

        scan.risk_score = result.get("risk_score", 0)
        scan.raw_output = result.get("raw", {})
        scan.status = "done"
        scan.completed_at = datetime.utcnow()
        scan.error_message = None

        db.commit()

        print(f"[SCAN] Completed successfully: {scan_id}", flush=True)

    except Exception as exc:
        if db is not None:
            try:
                db.rollback()

                scan = (
                    db.query(models.Scan)
                    .filter(models.Scan.id == scan_id)
                    .first()
                )

                if scan:
                    scan.status = "failed"
                    scan.error_message = (
                        f"{type(exc).__name__}: {exc}"
                    )[:2000]
                    scan.completed_at = datetime.utcnow()
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
):
    scan = models.Scan(
        image_name=req.image_name,
        status="pending",
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_execute_scan, scan.id)

    return scan


@app.get("/scan/{scan_id}", response_model=schemas.ScanDetailOut)
def get_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    scan = (
        db.query(models.Scan)
        .filter(models.Scan.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@app.get("/scans", response_model=list[schemas.ScanStatusOut])
def list_scans(db: Session = Depends(get_db)):
    return (
        db.query(models.Scan)
        .order_by(models.Scan.created_at.desc())
        .limit(50)
        .all()
    )


@app.get("/scan/{scan_id}/report")
def download_report(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    scan = (
        db.query(models.Scan)
        .filter(models.Scan.id == scan_id)
        .first()
    )

    if not scan:
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
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        },
    )
