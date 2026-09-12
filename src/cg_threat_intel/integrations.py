from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from cg_threat_intel.adapters.context import RequestContext, get_request_context
from cg_threat_intel.config import get_settings
from cg_threat_intel.db import get_db
from cg_threat_intel.models import ExaIntegration
from cg_threat_intel.schemas import ExaIntegrationCreate

router = APIRouter(tags=["integrations"])

@router.get("/integrations/exa")
def exa_status(context: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)) -> dict:
    integration = db.scalar(select(ExaIntegration).where(ExaIntegration.tenant_id == context.tenant_id))
    return {"configured": integration is not None, "status": integration.status if integration else "not_configured"}

@router.post("/integrations/exa")
def save_exa(payload: ExaIntegrationCreate, context: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)) -> dict:
    key = get_settings().local_encryption_key
    if key is None: raise HTTPException(status_code=503, detail="Local encryption key is not configured.")
    try: encrypted = Fernet(key.get_secret_value().encode()).encrypt(payload.api_key.encode()).decode()
    except Exception as error: raise HTTPException(status_code=503, detail="Local encryption key is invalid.") from error
    integration = db.scalar(select(ExaIntegration).where(ExaIntegration.tenant_id == context.tenant_id))
    if integration is None:
        integration = ExaIntegration(tenant_id=context.tenant_id, encrypted_api_key=encrypted); db.add(integration)
    else: integration.encrypted_api_key = encrypted; integration.status = "configured"
    db.commit()
    return {"status": integration.status, "configured": True}
