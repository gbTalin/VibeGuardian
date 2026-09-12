import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from cg_threat_intel.config import get_settings
from cg_threat_intel.db import Base, engine
from cg_threat_intel.main import app


@pytest.fixture(autouse=True)
def clean_database_and_config(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setenv("CG_EXA_WEBHOOK_SECRET", "test-webhook-secret")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _signature(body: bytes) -> str:
    timestamp = "1704729600"
    signed_payload = timestamp.encode() + b"." + body
    digest = hmac.new(b"test-webhook-secret", signed_payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def test_exa_webhook_is_verified_and_idempotent() -> None:
    event = {
        "id": "event_123",
        "type": "monitor.run.completed",
        "data": {"id": "run_123", "monitorId": "mon_123", "status": "completed"},
    }
    body = json.dumps(event, separators=(",", ":")).encode()
    headers = {"Exa-Signature": _signature(body), "Content-Type": "application/json"}
    client = TestClient(app)

    created = client.post("/v1/webhooks/exa/monitors", content=body, headers=headers)
    duplicate = client.post("/v1/webhooks/exa/monitors", content=body, headers=headers)

    assert created.status_code == 200
    assert created.json() == {
        "event_id": "event_123",
        "processing_state": "pending_validation",
        "duplicate": False,
    }
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True


def test_exa_webhook_rejects_invalid_signature() -> None:
    client = TestClient(app)
    response = client.post(
        "/v1/webhooks/exa/monitors",
        content=b'{"id":"event_123"}',
        headers={"Exa-Signature": "t=1,v1=not-valid"},
    )

    assert response.status_code == 401
