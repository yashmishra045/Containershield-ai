import uuid
from datetime import datetime

from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from .database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    image_name = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending / running / done / failed
    risk_score = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)
    raw_output = Column(JSONB, nullable=True)  # full tool outputs, for debugging/audit
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    vulnerabilities = relationship(
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan"
    )
    secrets = relationship(
        "Secret", back_populates="scan", cascade="all, delete-orphan"
    )
    sbom_components = relationship(
        "SBOMComponent", back_populates="scan", cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"))
    cve_id = Column(String)
    package = Column(String)
    installed_version = Column(String)
    fixed_version = Column(String, nullable=True)
    severity = Column(String)  # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    source_tool = Column(String)  # trivy / grype
    description = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="vulnerabilities")


class Secret(Base):
    __tablename__ = "secrets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"))
    file_path = Column(String)
    rule_id = Column(String)
    match_snippet = Column(String)  # redacted / truncated match

    scan = relationship("Scan", back_populates="secrets")


class SBOMComponent(Base):
    __tablename__ = "sbom_components"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"))
    component_name = Column(String)
    version = Column(String)
    component_type = Column(String)  # library / os-package / etc

    scan = relationship("Scan", back_populates="sbom_components")
