import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from cg_threat_intel.config import get_settings
from cg_threat_intel.db import get_db
from cg_threat_intel.models import IntelligenceEvent
from cg_threat_intel.schemas import ExaWebhookReceipt
from cg_threat_intel.services.exa_intelligence import extract_exa_intelligence_lead
from cg_threat_intel.services.exa_webhooks import WebhookSignatureError, verify_exa_signature

router = APIRouter(tags=["webhooks"])


@router.post("/webhooks/exa/monitors", response_model=ExaWebhookReceipt)
async def receive_exa_monitor_event(request: Request, db: Session = Depends(get_db)) -> ExaWebhookReceipt:
    secret = get_settings().exa_webhook_secret
    if secret is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Exa webhook intake is not configured.",
        )
    body = await request.body()
    try:
        verify_exa_signature(
            body=body,
            signature_header=request.headers.get("Exa-Signature"),
            secret=secret.get_secret_value(),
        )
    except WebhookSignatureError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook signature.") from error
    try:
        event = json.loads(body)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Webhook body must be JSON.") from error

    payload_hash = hashlib.sha256(body).hexdigest()
    existing = db.scalar(select(IntelligenceEvent).where(IntelligenceEvent.payload_hash == payload_hash))
    if existing is not None:
        return ExaWebhookReceipt(
            event_id=existing.provider_event_id,
            processing_state=existing.processing_state,
            duplicate=True,
        )

    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    lead = extract_exa_intelligence_lead(data)
    event_type = event.get("type")
    processing_state = "pending_validation" if event_type == "monitor.run.completed" else "ignored"
    intelligence_event = IntelligenceEvent(
        provider="exa",
        provider_event_id=event.get("id"),
        monitor_id=data.get("monitorId"),
        payload_hash=payload_hash,
        processing_state=processing_state,
        payload={
            "id": event.get("id"),
            "type": event_type,
            "created_at": event.get("createdAt"),
            "monitor_id": data.get("monitorId"),
            "run_id": data.get("id"),
            "run_status": data.get("status"),
            "candidate_identifiers": lead.candidate_identifiers,
            "source_urls": lead.source_urls,
        },
    )
    db.add(intelligence_event)
    db.commit()
    return ExaWebhookReceipt(
        event_id=intelligence_event.provider_event_id,
        processing_state=processing_state,
        duplicate=False,
    )
