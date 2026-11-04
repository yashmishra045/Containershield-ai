import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScanRequest(BaseModel):
    image_name: str = Field(min_length=1, max_length=512)


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    package: str
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    severity: str
    source_tool: str
    description: Optional[str] = None


class SecretOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    file_path: str
    rule_id: str
    match_snippet: str


class SBOMComponentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    component_name: str
    version: Optional[str] = None
    component_type: Optional[str] = None


class ScanStatusOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    image_name: str
    status: str
    progress: int = 0
    current_stage: Optional[str] = None
    risk_score: float
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class ScanDetailOut(ScanStatusOut):
    vulnerabilities: List[VulnerabilityOut] = Field(default_factory=list)
    secrets: List[SecretOut] = Field(default_factory=list)
    sbom_components: List[SBOMComponentOut] = Field(default_factory=list)


class SignupRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=10, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    id: uuid.UUID
    full_name: str
    email: str
    role: str

    model_config = ConfigDict(from_attributes=True)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class AdminUserOut(BaseModel):
    id: uuid.UUID
    full_name: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None
    scan_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class LoginHistoryOut(BaseModel):
    full_name: str
    email: str
    logged_in_at: datetime
