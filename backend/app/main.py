import uuid
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy.orm import Session

from . import models, schemas, scanner, report
from .database import engine, get_db, Base

# Create tables on startup (fine for dev; use Alembic migrations in production)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="ContainerShield AI", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _execute_scan(scan_id: uuid.UUID):
    """Runs in a background thread: calls the scanner tools and writes
    results to the database."""
    db: Session = next(get_db())
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        return
    scan.status = "running"
    db.commit()

    try:
        result = scanner.run_full_scan(scan.image_name)

        for v in result["vulnerabilities"]:
            db.add(models.Vulnerability(scan_id=scan.id, **v))
        for s in result["secrets"]:
            db.add(models.Secret(scan_id=scan.id, **s))
        for c in result["sbom_components"]:
            db.add(models.SBOMComponent(scan_id=scan.id, **c))

        scan.risk_score = result["risk_score"]
        scan.raw_output = result["raw"]
        scan.status = "done"
        scan.completed_at = datetime.utcnow()
        db.commit()

    except scanner.ToolNotFoundError as e:
        scan.status = "failed"
        scan.error_message = str(e)
        db.commit()
    except Exception as e:  # noqa: BLE001 - want to persist any failure reason
        scan.status = "failed"
        scan.error_message = str(e)[:2000]
        db.commit()
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan", response_model=schemas.ScanStatusOut)
def create_scan(
    req: schemas.ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    scan = models.Scan(image_name=req.image_name, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_execute_scan, scan.id)
    return scan


@app.get("/scan/{scan_id}", response_model=schemas.ScanDetailOut)
def get_scan(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/scans", response_model=list[schemas.ScanStatusOut])
def list_scans(db: Session = Depends(get_db)):
    return db.query(models.Scan).order_by(models.Scan.created_at.desc()).limit(50).all()


@app.get("/scan/{scan_id}/report")
def download_report(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "done":
        raise HTTPException(status_code=400, detail=f"Scan is not complete (status: {scan.status})")

    pdf_bytes = report.generate_pdf_report(
        scan, scan.vulnerabilities, scan.secrets, scan.sbom_components
    )
    filename = f"containershield-report-{scan.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
