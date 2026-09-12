from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException
import httpx
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from cg_threat_intel.adapters.context import RequestContext, get_request_context
from cg_threat_intel.config import get_settings
from cg_threat_intel.db import get_db
from cg_threat_intel.models import ExaIntegration

router = APIRouter(tags=["demo"])

class MonitorNow(BaseModel):
    app_name: str = Field(min_length=1, max_length=120)
    stack: str = Field(default="", max_length=2000)
    public_url: str | None = Field(default=None, max_length=2048)

@router.post("/demo/monitor-now")
def monitor_now(payload: MonitorNow, context: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)) -> dict:
    integration = db.scalar(select(ExaIntegration).where(ExaIntegration.tenant_id == context.tenant_id))
    secret = get_settings().local_encryption_key
    if integration is None or secret is None:
        raise HTTPException(status_code=409, detail="Save an Exa API key first.")
    try:
        api_key = Fernet(secret.get_secret_value().encode()).decrypt(integration.encrypted_api_key.encode()).decode()
        query = f"latest security vulnerabilities CVE exploits advisories affecting {payload.app_name} {payload.stack} {payload.public_url or ''}"
        response = httpx.post("https://api.exa.ai/search", headers={"Authorization": f"Bearer {api_key}"}, json={"query": query, "numResults": 6, "contents": {"highlights": True}}, timeout=20)
        response.raise_for_status()
    except httpx.HTTPError as error:
        raise HTTPException(status_code=502, detail="Exa search failed. Check the API key and try again.") from error
    data = response.json()
    results = [{"title": item.get("title"), "url": item.get("url"), "published_date": item.get("publishedDate"), "highlights": item.get("highlights", [])} for item in data.get("results", [])]
    return {"app_name": payload.app_name, "query": query, "result_count": len(results), "results": results}
