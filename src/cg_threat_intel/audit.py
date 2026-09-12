import hashlib
import json

from sqlalchemy.orm import Session

from cg_threat_intel.models import AuditEvent


def record_audit_event(
    db: Session,
    *,
    tenant_id: str,
    actor_id: str | None,
    action: str,
    target_type: str,
    target_id: str,
    payload: dict,
) -> AuditEvent:
    serialized_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    event = AuditEvent(
        tenant_id=tenant_id,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        payload=payload,
        payload_hash=hashlib.sha256(serialized_payload.encode()).hexdigest(),
    )
    db.add(event)
    return event

