import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    full_name = Column(String(120), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False, default="user")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = Column(DateTime, nullable=True)

    scans = relationship("Scan", back_populates="user")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # NULL is retained for legacy scans created before authentication.
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    image_name = Column(String, nullable=False)
    status = Column(String, default="pending")
    progress = Column(Integer, default=0, nullable=False)
    current_stage = Column(String, default="Queued", nullable=True)
    risk_score = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)
    raw_output = Column(JSONB, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    secrets = relationship("Secret", back_populates="scan", cascade="all, delete-orphan")
    sbom_components = relationship("SBOMComponent", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"))
    cve_id = Column(String)
    package = Column(String)
    installed_version = Column(String)
    fixed_version = Column(String, nullable=True)
    severity = Column(String)
    source_tool = Column(String)
    description = Column(Text, nullable=True)
    scan = relationship("Scan", back_populates="vulnerabilities")


class Secret(Base):
    __tablename__ = "secrets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"))
    file_path = Column(String)
    rule_id = Column(String)
    match_snippet = Column(String)
    scan = relationship("Scan", back_populates="secrets")


class SBOMComponent(Base):
    __tablename__ = "sbom_components"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"))
    component_name = Column(String)
    version = Column(String)
    component_type = Column(String)
    scan = relationship("Scan", back_populates="sbom_components")


class LoginEvent(Base):
    __tablename__ = "login_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    logged_in_at = Column(DateTime, default=datetime.utcnow, nullable=False)
