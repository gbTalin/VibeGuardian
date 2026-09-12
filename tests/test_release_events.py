import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from cg_threat_intel import release_events
from cg_threat_intel.config import get_settings
from cg_threat_intel.db import Base, engine
from cg_threat_intel.main import app


@pytest.fixture(autouse=True)
def clean_database_and_config(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setenv("CG_RELEASE_WEBHOOK_SECRET", "release-test-secret")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _signature(body: bytes) -> str:
    timestamp = "1704729600"
    signed_payload = timestamp.encode() + b"." + body
    digest = hmac.new(b"release-test-secret", signed_payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def test_release_event_is_verified_deduplicated_and_does_not_store_raw_artifact(monkeypatch) -> None:
    client = TestClient(app)
    application = client.post(
        "/v1/applications",
        headers={"X-CG-Tenant-ID": "tenant-a", "X-CG-Actor-ID": "admin-a"},
        json={"name": "Published API"},
    ).json()

    class ScanResult:
        scan_id = "scan-123"

    monkeypatch.setattr(release_events, "_scan_dependencies", lambda **_: ScanResult())
    event = {
        "event_id": "release-event-1",
        "tenant_id": "tenant-a",
        "application_id": application["id"],
        "release_id": "release-42",
        "artifact_type": "requirements",
        "content": "Django==4.2.0\n",
    }
    body = json.dumps(event, separators=(",", ":")).encode()
    headers = {"X-CG-Release-Signature": _signature(body), "Content-Type": "application/json"}

    created = client.post("/v1/integrations/release-events", content=body, headers=headers)
    duplicate = client.post("/v1/integrations/release-events", content=body, headers=headers)

    assert created.json() == {"scan_id": "scan-123", "duplicate": False}
    assert duplicate.json() == {"scan_id": "scan-123", "duplicate": True}
