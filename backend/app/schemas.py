import uuid
from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, ConfigDict


class ScanRequest(BaseModel):
    image_name: str


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
    risk_score: float
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class ScanDetailOut(ScanStatusOut):
    vulnerabilities: List[VulnerabilityOut] = []
    secrets: List[SecretOut] = []
    sbom_components: List[SBOMComponentOut] = []
