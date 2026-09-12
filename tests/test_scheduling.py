from datetime import UTC, datetime

from cg_threat_intel.db import Base, SessionLocal, engine
from cg_threat_intel.models import Application, MonitoringPolicy
from cg_threat_intel.services.scheduling import calculate_next_run, enqueue_due_scheduled_scans


def test_scheduled_policy_creates_a_queued_scan_when_due() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    now = datetime(2026, 9, 12, 9, 0, tzinfo=UTC)
    db = SessionLocal()
    application = Application(tenant_id="tenant-a", name="Published API")
    db.add(application)
    db.flush()
    policy = MonitoringPolicy(
        application_id=application.id,
        mode="scheduled",
        schedule_expression="0 * * * *",
        timezone="UTC",
        next_run_at=now,
        scan_scope={"analyzer": "python_requirements", "artifact_ref": "release:42"},
    )
    db.add(policy)
    db.commit()

    scans = enqueue_due_scheduled_scans(db, now)
    db.commit()

    assert len(scans) == 1
    assert scans[0].trigger == "scheduled"
    assert scans[0].status == "queued"
    assert policy.next_run_at.replace(tzinfo=UTC) == datetime(2026, 9, 12, 10, 0, tzinfo=UTC)
    db.close()


def test_next_run_is_calculated_in_the_policy_timezone() -> None:
    policy = MonitoringPolicy(
        application_id="application-a",
        mode="scheduled",
        schedule_expression="0 2 * * *",
        timezone="America/Los_Angeles",
    )

    next_run = calculate_next_run(policy, datetime(2026, 9, 12, 8, 0, tzinfo=UTC))

    assert next_run == datetime(2026, 9, 12, 9, 0, tzinfo=UTC)
