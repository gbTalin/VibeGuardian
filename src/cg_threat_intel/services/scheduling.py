from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from croniter import croniter
from sqlalchemy import select
from sqlalchemy.orm import Session

from cg_threat_intel.models import MonitoringPolicy, Scan


def calculate_next_run(policy: MonitoringPolicy, now: datetime) -> datetime | None:
    if policy.mode not in {"scheduled", "continuous_and_scheduled"}:
        return None
    if not policy.schedule_expression or not policy.timezone:
        raise ValueError("Scheduled policies must have a schedule expression and timezone.")
    local_now = now.astimezone(ZoneInfo(policy.timezone))
    return croniter(policy.schedule_expression, local_now).get_next(datetime).astimezone(UTC)


def enqueue_due_scheduled_scans(db: Session, now: datetime) -> list[Scan]:
    """Create queued jobs for due policies; workers execute only stored approved scope."""

    policies = db.scalars(
        select(MonitoringPolicy).where(
            MonitoringPolicy.enabled.is_(True),
            MonitoringPolicy.mode.in_(("scheduled", "continuous_and_scheduled")),
            MonitoringPolicy.next_run_at.is_not(None),
            MonitoringPolicy.next_run_at <= now,
        )
    )
    scans: list[Scan] = []
    for policy in policies:
        scan = Scan(
            application_id=policy.application_id,
            trigger="scheduled",
            status="queued",
            scope=policy.scan_scope,
            initiated_by=f"monitoring_policy:{policy.id}",
        )
        db.add(scan)
        policy.last_run_at = now
        policy.next_run_at = calculate_next_run(policy, now)
        scans.append(scan)
    return scans
