import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from cg_threat_intel.db import Base


def new_id() -> str:
    return str(uuid.uuid4())


class Application(Base):
    __tablename__ = "applications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    external_application_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    environment: Mapped[str] = mapped_column(String(32), default="production")
    criticality: Mapped[str] = mapped_column(String(32), default="standard")
    status: Mapped[str] = mapped_column(String(32), default="needs_review")
    authorization_state: Mapped[str] = mapped_column(String(32), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    asset_type: Mapped[str] = mapped_column(String(32))
    identifier: Mapped[str] = mapped_column(String(512))
    package_purl: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    trigger: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="queued")
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    initiated_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    vulnerability_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    state: Mapped[str] = mapped_column(String(32), default="new")
    match_confidence: Mapped[str] = mapped_column(String(32), default="needs_review")
    intrinsic_severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    adjusted_priority: Mapped[str | None] = mapped_column(String(32), nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class MonitoringPolicy(Base):
    __tablename__ = "monitoring_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    mode: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(default=True)
    monitor_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    schedule_expression: Mapped[str | None] = mapped_column(String(128), nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scan_scope: Mapped[dict] = mapped_column(JSON, default=dict)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class IntelligenceEvent(Base):
    __tablename__ = "intelligence_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    provider: Mapped[str] = mapped_column(String(64))
    provider_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    monitor_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    payload_hash: Mapped[str] = mapped_column(String(128), unique=True)
    processing_state: Mapped[str] = mapped_column(String(32), default="received")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ReleaseArtifact(Base):
    __tablename__ = "release_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    external_event_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    external_release_id: Mapped[str] = mapped_column(String(255), index=True)
    artifact_type: Mapped[str] = mapped_column(String(64))
    content_hash: Mapped[str] = mapped_column(String(128))
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DomainVerification(Base):
    __tablename__ = "domain_verifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    target_url: Mapped[str] = mapped_column(String(2048))
    token: Mapped[str] = mapped_column(String(128), unique=True)
    state: Mapped[str] = mapped_column(String(32), default="pending")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ExaIntegration(Base):
    __tablename__ = "exa_integrations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    encrypted_api_key: Mapped[str] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(String(32), default="configured")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    target_type: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    payload_hash: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
