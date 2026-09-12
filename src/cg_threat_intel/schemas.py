from datetime import datetime
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ApplicationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    external_application_id: str | None = Field(default=None, max_length=128)
    environment: str = Field(default="production", max_length=32)
    criticality: str = Field(default="standard", max_length=32)


class ApplicationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    external_application_id: str | None
    name: str
    environment: str
    criticality: str
    status: str
    authorization_state: str
    created_at: datetime


class RequirementsScanRequest(BaseModel):
    content: str = Field(min_length=1, max_length=1_000_000)


class DependencyArtifactScanRequest(BaseModel):
    artifact_type: Literal["requirements", "poetry_lock", "pipfile_lock", "cyclonedx_json", "spdx_json"]
    content: str = Field(min_length=1, max_length=5_000_000)


class DependencyFindingRead(BaseModel):
    dependency_name: str
    dependency_version: str
    purl: str
    vulnerability_id: str
    summary: str
    severity: str | None
    references: list[str]


class RequirementsScanRead(BaseModel):
    scan_id: str
    dependency_count: int
    finding_count: int
    findings: list[DependencyFindingRead]


class MonitoringPolicyCreate(BaseModel):
    mode: Literal["continuous", "scheduled", "continuous_and_scheduled"]
    monitor_id: str | None = Field(default=None, max_length=255)
    schedule_expression: str | None = Field(default=None, max_length=128)
    timezone: str | None = Field(default=None, max_length=64)
    scan_scope: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_schedule(self) -> "MonitoringPolicyCreate":
        scheduled = self.mode in {"scheduled", "continuous_and_scheduled"}
        if scheduled and not self.schedule_expression:
            raise ValueError("Scheduled monitoring requires a schedule expression.")
        if scheduled and not self.timezone:
            raise ValueError("Scheduled monitoring requires an IANA timezone.")
        if self.mode in {"continuous", "continuous_and_scheduled"} and not self.monitor_id:
            raise ValueError("Continuous monitoring requires an Exa monitor identifier.")
        if self.timezone:
            try:
                ZoneInfo(self.timezone)
            except ZoneInfoNotFoundError as error:
                raise ValueError("Timezone must be a valid IANA timezone.") from error
        return self


class MonitoringPolicyUpdate(BaseModel):
    enabled: bool


class MonitoringPolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    application_id: str
    mode: str
    enabled: bool
    monitor_id: str | None
    schedule_expression: str | None
    timezone: str | None
    scan_scope: dict


class ExaWebhookReceipt(BaseModel):
    event_id: str | None
    processing_state: str
    duplicate: bool


class ReleaseArtifactWebhook(DependencyArtifactScanRequest):
    event_id: str = Field(min_length=1, max_length=255)
    tenant_id: str = Field(min_length=1, max_length=128)
    application_id: str = Field(min_length=1, max_length=36)
    release_id: str = Field(min_length=1, max_length=255)


class ReleaseArtifactReceipt(BaseModel):
    scan_id: str | None
    duplicate: bool


class DomainVerificationCreate(BaseModel):
    target_url: str = Field(min_length=12, max_length=2048)


class DomainVerificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_url: str
    token: str
    state: str


class PostureScanRead(BaseModel):
    scan_id: str
    status: str
    finding_count: int


class FindingUpdate(BaseModel):
    state: Literal["triaged", "in_progress", "mitigated", "resolved", "accepted_risk", "false_positive"]


class ExaIntegrationCreate(BaseModel):
    api_key: str = Field(min_length=10, max_length=512)
