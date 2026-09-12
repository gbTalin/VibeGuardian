from dataclasses import dataclass

from fastapi import Header, HTTPException, status


@dataclass(frozen=True)
class RequestContext:
    """Development adapter for CyberGuard tenant and actor context."""

    tenant_id: str
    actor_id: str


async def get_request_context(
    x_cg_tenant_id: str | None = Header(default=None),
    x_cg_actor_id: str | None = Header(default=None),
) -> RequestContext:
    if not x_cg_tenant_id or not x_cg_actor_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="CyberGuard tenant and actor context are required.",
        )
    return RequestContext(tenant_id=x_cg_tenant_id, actor_id=x_cg_actor_id)

