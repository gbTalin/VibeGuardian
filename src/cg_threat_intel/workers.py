from datetime import UTC, datetime

from celery import Celery

from cg_threat_intel.config import get_settings
from cg_threat_intel.db import SessionLocal
from cg_threat_intel.models import IntelligenceEvent
from cg_threat_intel.services.intelligence_processing import process_exa_intelligence_event
from cg_threat_intel.services.osv import OsvClient
from cg_threat_intel.services.scheduling import enqueue_due_scheduled_scans

settings = get_settings()
celery_app = Celery("cyberguard_threat_intel", broker=settings.redis_url)
celery_app.conf.beat_schedule = {
    "dispatch-due-security-scans": {
        "task": "cg_threat_intel.workers.dispatch_due_scheduled_scans",
        "schedule": 60.0,
    },
    "process-pending-exa-intelligence": {
        "task": "cg_threat_intel.workers.process_pending_exa_intelligence",
        "schedule": 60.0,
    },
}


@celery_app.task(name="cg_threat_intel.workers.dispatch_due_scheduled_scans")
def dispatch_due_scheduled_scans() -> int:
    """Celery Beat runs this periodically; individual scan workers consume queued work."""

    db = SessionLocal()
    try:
        scans = enqueue_due_scheduled_scans(db, datetime.now(UTC))
        db.commit()
        return len(scans)
    finally:
        db.close()


@celery_app.task(name="cg_threat_intel.workers.process_pending_exa_intelligence")
def process_pending_exa_intelligence() -> int:
    """Validate pending Exa leads through OSV before they can affect findings."""

    db = SessionLocal()
    client = OsvClient()
    try:
        events = list(
            db.query(IntelligenceEvent)
            .filter(IntelligenceEvent.provider == "exa", IntelligenceEvent.processing_state == "pending_validation")
            .all()
        )
        count = sum(process_exa_intelligence_event(db, event, client) for event in events)
        db.commit()
        return count
    finally:
        client.close()
        db.close()
