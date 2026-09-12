from cg_threat_intel.db import Base, SessionLocal, engine
from cg_threat_intel.models import Application, Asset, IntelligenceEvent, MonitoringPolicy
from cg_threat_intel.services.intelligence_processing import process_exa_intelligence_event
from cg_threat_intel.services.osv import OsvVulnerability


class StubOsvClient:
    def query_python_dependencies(self, dependencies):
        return {
            "django": [
                OsvVulnerability(
                    id="GHSA-aaaa-bbbb-cccc",
                    summary="An affected Django version.",
                    aliases=["CVE-2026-12345"],
                    severity="HIGH",
                    references=["https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc"],
                )
            ]
        }


def test_exa_event_requires_an_authoritative_version_match_before_creating_finding() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    application = Application(tenant_id="tenant-a", name="Published API")
    db.add(application)
    db.flush()
    db.add(
        Asset(
            application_id=application.id,
            asset_type="python_dependency",
            identifier="django",
            package_purl="pkg:pypi/django@4.2.0",
            version="4.2.0",
        )
    )
    db.add(MonitoringPolicy(application_id=application.id, mode="continuous", monitor_id="mon_django"))
    event = IntelligenceEvent(
        provider="exa",
        provider_event_id="event-1",
        monitor_id="mon_django",
        payload_hash="unique-event-1",
        processing_state="pending_validation",
        payload={
            "candidate_identifiers": ["CVE-2026-12345"],
            "source_urls": ["https://vendor.example/advisory"],
        },
    )
    db.add(event)
    db.commit()

    count = process_exa_intelligence_event(db, event, StubOsvClient())
    db.commit()

    assert count == 1
    assert event.processing_state == "processed"
    assert db.query(Asset).count() == 1
    assert db.query(IntelligenceEvent).count() == 1
    db.close()
