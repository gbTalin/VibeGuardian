from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from cg_threat_intel.services.targets import validate_public_https_target


@dataclass(frozen=True)
class ExternalPostureResult:
    target: str
    status_code: int
    redirect_location: str | None
    headers: dict[str, str]
    observed_at: datetime


def inspect_public_https_target(target: str, client: httpx.Client | None = None) -> ExternalPostureResult:
    """Perform one bounded, non-destructive HTTPS request; never follow redirects."""

    target = validate_public_https_target(target)
    with (client or httpx.Client(timeout=10.0, follow_redirects=False)) as active_client:
        response = active_client.get(target, headers={"User-Agent": "CyberGuard-Posture/0.1"})
    selected_headers = {
        name: value
        for name, value in response.headers.items()
        if name.lower()
        in {"strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options"}
    }
    return ExternalPostureResult(
        target=target,
        status_code=response.status_code,
        redirect_location=response.headers.get("location"),
        headers=selected_headers,
        observed_at=datetime.now(UTC),
    )


def verify_domain_token(target: str, token: str, client: httpx.Client | None = None) -> bool:
    target = validate_public_https_target(target).rstrip("/")
    active_client = client or httpx.Client(timeout=10.0, follow_redirects=False)
    try:
        response = active_client.get(f"{target}/.well-known/cyberguard-verification.txt")
        return response.status_code == 200 and response.text.strip() == token
    finally:
        if client is None:
            active_client.close()
