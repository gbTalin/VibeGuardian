import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from cg_threat_intel.adapters.context import RequestContext
from cg_threat_intel.api import _get_application, _scan_dependencies
from cg_threat_intel.audit import record_audit_event
from cg_threat_intel.config import get_settings
from cg_threat_intel.db import get_db
from cg_threat_intel.models import ReleaseArtifact
from cg_threat_intel.schemas import ReleaseArtifactReceipt, ReleaseArtifactWebhook
from cg_threat_intel.services.artifacts import parse_dependency_artifact
from cg_threat_intel.services.exa_webhooks import WebhookSignatureError, verify_exa_signature
from cg_threat_intel.services.requirements import ManifestParseError

router = APIRouter(tags=["integrations"])


@router.post("/integrations/release-events", response_model=ReleaseArtifactReceipt)
async def receive_release_event(request: Request, db: Session = Depends(get_db)) -> ReleaseArtifactReceipt:
    secret = get_settings().release_webhook_secret
    if secret is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Release intake is not configured.")
    body = await request.body()
    try:
        verify_exa_signature(
            body=body,
            signature_header=request.headers.get("X-CG-Release-Signature"),
            secret=secret.get_secret_value(),
        )
    except WebhookSignatureError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid release signature.") from error
    try:
        payload = ReleaseArtifactWebhook.model_validate(json.loads(body))
    except (json.JSONDecodeError, ValidationError) as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid release event.") from error

    existing = db.scalar(select(ReleaseArtifact).where(ReleaseArtifact.external_event_id == payload.event_id))
    if existing is not None:
        return ReleaseArtifactReceipt(scan_id=existing.scan_id, duplicate=True)
    application = _get_application(db, payload.application_id, payload.tenant_id)
    try:
        artifact = parse_dependency_artifact(payload.artifact_type, payload.content)
    except ManifestParseError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)) from error

    result = _scan_dependencies(
        application_id=application.id,
        dependencies=artifact.dependencies,
        analyzer=artifact.artifact_type,
        trigger="release",
        scope_metadata={"external_release_id": payload.release_id, "external_event_id": payload.event_id},
        context=RequestContext(tenant_id=payload.tenant_id, actor_id="release_integration"),
        db=db,
    )
    release_artifact = ReleaseArtifact(
        tenant_id=payload.tenant_id,
        application_id=application.id,
        external_event_id=payload.event_id,
        external_release_id=payload.release_id,
        artifact_type=payload.artifact_type,
        content_hash=hashlib.sha256(payload.content.encode()).hexdigest(),
        scan_id=result.scan_id,
    )
    db.add(release_artifact)
    db.flush()
    record_audit_event(
        db,
        tenant_id=payload.tenant_id,
        actor_id="release_integration",
        action="release_artifact.received",
        target_type="release_artifact",
        target_id=release_artifact.id,
        payload={"release_id": payload.release_id, "artifact_type": payload.artifact_type, "scan_id": result.scan_id},
    )
    db.commit()
    return ReleaseArtifactReceipt(scan_id=result.scan_id, duplicate=False)
