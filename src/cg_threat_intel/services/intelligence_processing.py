from sqlalchemy import select
from sqlalchemy.orm import Session

from cg_threat_intel.audit import record_audit_event
from cg_threat_intel.models import Application, Asset, Finding, IntelligenceEvent, MonitoringPolicy
from cg_threat_intel.services.dependency_scan import correlate_python_dependencies
from cg_threat_intel.services.osv import VulnerabilityIntelligenceClient
from cg_threat_intel.services.requirements import PythonDependency


def process_exa_intelligence_event(
    db: Session, event: IntelligenceEvent, client: VulnerabilityIntelligenceClient
) -> int:
    """Validate an Exa lead against OSV and exact observed dependency versions.

    Exa can identify an emerging advisory, but a finding is created only when OSV
    confirms the candidate affects an observed package/version for a subscribed
    application.
    """

    if event.processing_state != "pending_validation":
        return 0
    candidates = set(event.payload.get("candidate_identifiers", []))
    if not candidates:
        event.processing_state = "review_required"
        return 0

    subscriptions = list(
        db.scalars(
            select(MonitoringPolicy).where(
                MonitoringPolicy.enabled.is_(True),
                MonitoringPolicy.mode.in_(("continuous", "continuous_and_scheduled")),
                MonitoringPolicy.monitor_id == event.monitor_id,
            )
        )
    )
    if not subscriptions:
        event.processing_state = "no_subscriptions"
        return 0

    finding_count = 0
    for subscription in subscriptions:
        application = db.get(Application, subscription.application_id)
        if application is None:
            continue
        assets = list(
            db.scalars(
                select(Asset).where(
                    Asset.application_id == application.id,
                    Asset.asset_type == "python_dependency",
                    Asset.version.is_not(None),
                )
            )
        )
        dependencies = [
            PythonDependency(name=asset.identifier, version=asset.version) for asset in assets if asset.version
        ]
        assets_by_package = {asset.identifier: asset for asset in assets}
        for match in correlate_python_dependencies(dependencies, client):
            identifiers = {match.vulnerability.id, *match.vulnerability.aliases}
            if not candidates.intersection(identifier.upper() for identifier in identifiers):
                continue
            _upsert_exa_correlated_finding(db, application, assets_by_package[match.dependency.normalized_name], match, event)
            finding_count += 1

    event.processing_state = "processed" if finding_count else "validated_no_match"
    return finding_count


def _upsert_exa_correlated_finding(db: Session, application: Application, asset: Asset, match, event: IntelligenceEvent) -> None:
    finding = db.scalar(
        select(Finding).where(
            Finding.application_id == application.id,
            Finding.asset_id == asset.id,
            Finding.vulnerability_id == match.vulnerability.id,
        )
    )
    evidence = {
        "source": "OSV",
        "package": match.dependency.normalized_name,
        "version": match.dependency.version,
        "purl": match.dependency.purl,
        "references": match.vulnerability.references,
        "exa_intelligence_event_id": event.id,
        "exa_source_urls": event.payload.get("source_urls", []),
    }
    if finding is None:
        finding = Finding(
            application_id=application.id,
            asset_id=asset.id,
            vulnerability_id=match.vulnerability.id,
            state="new",
            match_confidence="confirmed",
            intrinsic_severity=match.vulnerability.severity,
            adjusted_priority=match.vulnerability.severity,
            evidence=evidence,
        )
        db.add(finding)
    else:
        finding.evidence = evidence
        finding.match_confidence = "confirmed"
        finding.intrinsic_severity = match.vulnerability.severity
        finding.adjusted_priority = match.vulnerability.severity
        if finding.state in {"resolved", "false_positive"}:
            finding.state = "reopened"
    db.flush()
    record_audit_event(
        db,
        tenant_id=application.tenant_id,
        actor_id="exa_monitor",
        action="finding.correlated_from_intelligence",
        target_type="finding",
        target_id=finding.id,
        payload={"vulnerability_id": match.vulnerability.id, "intelligence_event_id": event.id},
    )
