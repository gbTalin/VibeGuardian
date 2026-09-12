import pytest
from fastapi.testclient import TestClient

from cg_threat_intel.db import Base, engine
from cg_threat_intel.main import app

client = TestClient(app)
HEADERS = {"X-CG-Tenant-ID": "tenant-a", "X-CG-Actor-ID": "admin-a"}


@pytest.fixture(autouse=True)
def clean_database() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_health() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_application_is_scoped_to_tenant() -> None:
    created = client.post("/v1/applications", headers=HEADERS, json={"name": "Published API"})

    assert created.status_code == 201
    assert created.json()["name"] == "Published API"

    same_tenant = client.get("/v1/applications", headers=HEADERS)
    other_tenant = client.get(
        "/v1/applications",
        headers={"X-CG-Tenant-ID": "tenant-b", "X-CG-Actor-ID": "admin-b"},
    )

    assert len(same_tenant.json()) == 1
    assert other_tenant.json() == []


def test_tenant_context_is_required() -> None:
    response = client.get("/v1/applications")

    assert response.status_code == 401


def test_scheduled_monitoring_policy_requires_a_timezone() -> None:
    application = client.post("/v1/applications", headers=HEADERS, json={"name": "Published API"}).json()

    response = client.post(
        f"/v1/applications/{application['id']}/monitoring-policies",
        headers=HEADERS,
        json={"mode": "scheduled", "schedule_expression": "0 2 * * *"},
    )

    assert response.status_code == 422


def test_monitoring_policy_can_be_created_and_paused() -> None:
    application = client.post("/v1/applications", headers=HEADERS, json={"name": "Published API"}).json()
    created = client.post(
        f"/v1/applications/{application['id']}/monitoring-policies",
        headers=HEADERS,
        json={
            "mode": "continuous_and_scheduled",
            "monitor_id": "mon_python_security",
            "schedule_expression": "0 2 * * *",
            "timezone": "America/Los_Angeles",
        },
    )

    assert created.status_code == 201
    paused = client.patch(
        f"/v1/monitoring-policies/{created.json()['id']}", headers=HEADERS, json={"enabled": False}
    )
    assert paused.status_code == 200
    assert paused.json()["enabled"] is False
