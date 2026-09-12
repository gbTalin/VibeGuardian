
import secrets
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from cg_threat_intel.adapters.context import RequestContext, get_request_context
from cg_threat_intel.audit import record_audit_event
from cg_threat_intel.db import get_db
from cg_threat_intel.models import (
    Application,
    Asset,
    DomainVerification,
    Finding,
    MonitoringPolicy,
    Scan,
)
from cg_threat_intel.schemas import (
    ApplicationCreate,
    ApplicationRead,
    DependencyArtifactScanRequest,
    DependencyFindingRead,
    DomainVerificationCreate,
    DomainVerificationRead,
    FindingUpdate,
    MonitoringPolicyCreate,
    MonitoringPolicyRead,
    MonitoringPolicyUpdate,
    PostureScanRead,
    RequirementsScanRead,
    RequirementsScanRequest,
)
from cg_threat_intel.services.artifacts import parse_dependency_artifact
from cg_threat_intel.services.dependency_scan import correlate_python_dependencies
from cg_threat_intel.services.osv import OsvClient
from cg_threat_intel.services.posture import inspect_public_https_target, verify_domain_token
from cg_threat_intel.services.requirements import (
    ManifestParseError,
    PythonDependency,
    parse_pinned_requirements,
)
from cg_threat_intel.services.scheduling import calculate_next_run
from cg_threat_intel.services.targets import TargetValidationError, validate_public_https_target

router = APIRouter(tags=["applications"])


@router.post("/applications", response_model=ApplicationRead, status_code=status.HTTP_201_CREATED)
def create_application(
    payload: ApplicationCreate,
    context: RequestContext = Depends(get_request_context),
    db: Session = Depends(get_db),
) -> Application:
    application = Application(tenant_id=context.tenant_id, **payload.model_dump())
    db.add(application)
    db.flush()
    record_audit_event(
        db,
        tenant_id=context.tenant_id,
        actor_id=context.actor_id,
        action="application.created",
        target_type="application",
        target_id=application.id,
        payload={"name": application.name, "environment": application.environment},
    )
    db.commit()
    db.refresh(application)
    return application


@router.get("/applications", response_model=list[ApplicationRead])
def list_applications(
    context: RequestContext = Depends(get_request_context),
    db: Session = Depends(get_db),
) -> list[Application]:
    statement = (
        select(Application)
        .where(Application.tenant_id == context.tenant_id)
        .order_by(Application.created_at.desc())
    )
    return list(db.scalars(statement))


@router.post("/applications/{application_id}/domain-verifications", response_model=DomainVerificationRead, status_code=status.HTTP_201_CREATED)
def create_domain_verification(application_id: str, payload: DomainVerificationCreate, context: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)) -> DomainVerification:
    _get_application(db, application_id, context.tenant_id)
    try:
        target_url = validate_public_https_target(payload.target_url)
    except TargetValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    verification = DomainVerification(application_id=application_id, target_url=target_url, token=secrets.token_urlsafe(32))
    db.add(verification)
    db.commit(); db.refresh(verification)
    return verification


@router.post("/domain-verifications/{verification_id}/verify", response_model=DomainVerificationRead)
def verify_domain(verification_id: str, context: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)) -> DomainVerification:
    verification = db.scalar(select(DomainVerification).join(Application).where(DomainVerification.id == verification_id, Application.tenant_id == context.tenant_id))
    if verification is None:
        raise HTTPException(status_code=404, detail="Domain verification was not found.")
    try:
        valid = verify_domain_token(verification.target_url, verification.token)
    except Exception as error:
        raise HTTPException(status_code=503, detail="Domain verification target is temporarily unavailable.") from error
    if not valid:
        raise HTTPException(status_code=409, detail="Verification token was not found at the required path.")
    verification.state = "verified"; verification.verified_at = datetime.now(UTC)
    db.commit(); db.refresh(verification)
    return verification


@router.post("/applications/{application_id}/scans/posture", response_model=PostureScanRead)
def scan_posture(application_id: str, context: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)) -> PostureScanRead:
    application = _get_application(db, application_id, context.tenant_id)
    verification = db.scalar(select(DomainVerification).where(DomainVerification.application_id == application.id, DomainVerification.state == "verified"))
    if verification is None:
        raise HTTPException(status_code=409, detail="A verified public domain is required before posture scanning.")
    scan = Scan(application_id=application.id, trigger="manual", status="running", scope={"analyzer": "external_posture", "target": verification.target_url}, initiated_by=context.actor_id)
    db.add(scan); db.flush()
    try:
        result = inspect_public_https_target(verification.target_url)
    except Exception as error:
        scan.status = "failed"; db.commit()
        raise HTTPException(status_code=503, detail="Posture target is temporarily unavailable.") from error
    missing = [header for header in ("strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options") if header not in {name.lower() for name in result.headers}]
    asset = Asset(application_id=application.id, asset_type="public_https_target", identifier=verification.target_url)
    db.add(asset); db.flush()
    for header in missing:
        db.add(Finding(application_id=application.id, asset_id=asset.id, vulnerability_id=f"CONFIG-MISSING-{header.upper()}", state="new", match_confidence="confirmed", intrinsic_severity="LOW", adjusted_priority="LOW", evidence={"target": verification.target_url, "missing_header": header, "status_code": result.status_code}))
    scan.status = "completed"; application.status = "passed" if not missing else "needs_review"
    record_audit_event(db, tenant_id=context.tenant_id, actor_id=context.actor_id, action="scan.completed", target_type="scan", target_id=scan.id, payload={"analyzer": "external_posture", "finding_count": len(missing)})
    db.commit()
    return PostureScanRead(scan_id=scan.id, status=application.status, finding_count=len(missing))


@router.get("/applications/{application_id}/findings", response_model=None)
def list_findings(application_id: str, context: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)) -> list[Finding]:
    _get_application(db, application_id, context.tenant_id)
    return list(db.scalars(select(Finding).where(Finding.application_id == application_id)))


@router.patch("/findings/{finding_id}", response_model=None)
def update_finding(finding_id: str, payload: FindingUpdate, context: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)) -> Finding:
    finding = db.scalar(select(Finding).join(Application).where(Finding.id == finding_id, Application.tenant_id == context.tenant_id))
    if finding is None: raise HTTPException(status_code=404, detail="Finding was not found.")
    finding.state = payload.state
    record_audit_event(db, tenant_id=context.tenant_id, actor_id=context.actor_id, action="finding.updated", target_type="finding", target_id=finding.id, payload={"state": finding.state})
    db.commit(); db.refresh(finding)
    return finding


@router.get("/applications/{application_id}/posture")
def application_posture(application_id: str, context: RequestContext = Depends(get_request_context), db: Session = Depends(get_db)) -> dict:
    application = _get_application(db, application_id, context.tenant_id)
    findings = list(db.scalars(select(Finding).where(Finding.application_id == application.id)))
    active = [item for item in findings if item.state not in {"resolved", "false_positive", "accepted_risk"}]
    by_severity: dict[str, int] = {}
    for finding in active:
        severity = finding.intrinsic_severity or "unknown"
        by_severity[severity.lower()] = by_severity.get(severity.lower(), 0) + 1
    last_scan = db.scalar(select(Scan).where(Scan.application_id == application.id, Scan.status == "completed").order_by(Scan.completed_at.desc()))
    return {"application_id": application.id, "status": application.status, "active_findings": len(active), "findings_by_severity": by_severity, "last_scan_id": last_scan.id if last_scan else None}


@router.post(
    "/applications/{application_id}/monitoring-policies",
    response_model=MonitoringPolicyRead,
    status_code=status.HTTP_201_CREATED,
)
def create_monitoring_policy(
    application_id: str,
    payload: MonitoringPolicyCreate,
    context: RequestContext = Depends(get_request_context),
    db: Session = Depends(get_db),
) -> MonitoringPolicy:
    application = _get_application(db, application_id, context.tenant_id)
    policy = MonitoringPolicy(application_id=application.id, **payload.model_dump())
    policy.next_run_at = calculate_next_run(policy, datetime.now(UTC))
    db.add(policy)
    db.flush()
    record_audit_event(
        db,
        tenant_id=context.tenant_id,
        actor_id=context.actor_id,
        action="monitoring_policy.created",
        target_type="monitoring_policy",
        target_id=policy.id,
        payload={"mode": policy.mode, "enabled": policy.enabled},
    )
    db.commit()
    db.refresh(policy)
    return policy


@router.get("/applications/{application_id}/monitoring-policies", response_model=list[MonitoringPolicyRead])
def list_monitoring_policies(
    application_id: str,
    context: RequestContext = Depends(get_request_context),
    db: Session = Depends(get_db),
) -> list[MonitoringPolicy]:
    _get_application(db, application_id, context.tenant_id)
    return list(db.scalars(select(MonitoringPolicy).where(MonitoringPolicy.application_id == application_id)))


@router.patch("/monitoring-policies/{policy_id}", response_model=MonitoringPolicyRead)
def update_monitoring_policy(
    policy_id: str,
    payload: MonitoringPolicyUpdate,
    context: RequestContext = Depends(get_request_context),
    db: Session = Depends(get_db),
) -> MonitoringPolicy:
    policy = db.scalar(
        select(MonitoringPolicy)
        .join(Application)
        .where(MonitoringPolicy.id == policy_id, Application.tenant_id == context.tenant_id)
    )
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitoring policy was not found.")
    policy.enabled = payload.enabled
    record_audit_event(
        db,
        tenant_id=context.tenant_id,
        actor_id=context.actor_id,
        action="monitoring_policy.updated",
        target_type="monitoring_policy",
        target_id=policy.id,
        payload={"enabled": policy.enabled},
    )
    db.commit()
    db.refresh(policy)
    return policy


@router.post("/applications/{application_id}/scans/requirements", response_model=RequirementsScanRead)
def scan_requirements(
    application_id: str,
    payload: RequirementsScanRequest,
    context: RequestContext = Depends(get_request_context),
    db: Session = Depends(get_db),
) -> RequirementsScanRead:
    application = _get_application(db, application_id, context.tenant_id)
    try:
        dependencies = parse_pinned_requirements(payload.content)
    except ManifestParseError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)) from error

    scan = Scan(
        application_id=application.id,
        trigger="manual",
        status="running",
        scope={"analyzer": "python_requirements", "dependency_count": len(dependencies)},
        initiated_by=context.actor_id,
    )
    db.add(scan)
    db.flush()
    assets = {dependency.normalized_name: _upsert_asset(db, application.id, dependency) for dependency in dependencies}

    client = OsvClient()
    try:
        matches = correlate_python_dependencies(dependencies, client)
    except Exception as error:
        scan.status = "failed"
        record_audit_event(
            db,
            tenant_id=context.tenant_id,
            actor_id=context.actor_id,
            action="scan.failed",
            target_type="scan",
            target_id=scan.id,
            payload={"analyzer": "python_requirements", "reason": type(error).__name__},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Vulnerability intelligence is temporarily unavailable; retry the scan later.",
        ) from error
    finally:
        client.close()

    findings = [_upsert_finding(db, application.id, assets[match.dependency.normalized_name], match) for match in matches]
    scan.status = "completed"
    record_audit_event(
        db,
        tenant_id=context.tenant_id,
        actor_id=context.actor_id,
        action="scan.completed",
        target_type="scan",
        target_id=scan.id,
        payload={"analyzer": "python_requirements", "dependency_count": len(dependencies), "finding_count": len(findings)},
    )
    db.commit()

    return RequirementsScanRead(
        scan_id=scan.id,
        dependency_count=len(dependencies),
        finding_count=len(findings),
        findings=[
            DependencyFindingRead(
                dependency_name=match.dependency.name,
                dependency_version=match.dependency.version,
                purl=match.dependency.purl,
                vulnerability_id=match.vulnerability.id,
                summary=match.vulnerability.summary,
                severity=match.vulnerability.severity,
                references=match.vulnerability.references,
            )
            for match in matches
        ],
    )


@router.post("/applications/{application_id}/scans/dependencies", response_model=RequirementsScanRead)
def scan_dependency_artifact(
    application_id: str,
    payload: DependencyArtifactScanRequest,
    context: RequestContext = Depends(get_request_context),
    db: Session = Depends(get_db),
) -> RequirementsScanRead:
    try:
        artifact = parse_dependency_artifact(payload.artifact_type, payload.content)
    except ManifestParseError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)) from error
    return _scan_dependencies(
        application_id=application_id,
        dependencies=artifact.dependencies,
        analyzer=artifact.artifact_type,
        context=context,
        db=db,
    )


def _scan_dependencies(
    *,
    application_id: str,
    dependencies: list[PythonDependency],
    analyzer: str,
    context: RequestContext,
    db: Session,
    trigger: str = "manual",
    scope_metadata: dict | None = None,
) -> RequirementsScanRead:
    application = _get_application(db, application_id, context.tenant_id)
    scan = Scan(
        application_id=application.id,
        trigger=trigger,
        status="running",
        scope={"analyzer": analyzer, "dependency_count": len(dependencies), **(scope_metadata or {})},
        initiated_by=context.actor_id,
    )
    db.add(scan)
    db.flush()
    assets = {dependency.normalized_name: _upsert_asset(db, application.id, dependency) for dependency in dependencies}
    client = OsvClient()
    try:
        matches = correlate_python_dependencies(dependencies, client)
    except Exception as error:
        scan.status = "failed"
        record_audit_event(
            db,
            tenant_id=context.tenant_id,
            actor_id=context.actor_id,
            action="scan.failed",
            target_type="scan",
            target_id=scan.id,
            payload={"analyzer": analyzer, "reason": type(error).__name__},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Vulnerability intelligence is temporarily unavailable; retry the scan later.",
        ) from error
    finally:
        client.close()
    findings = [_upsert_finding(db, application.id, assets[match.dependency.normalized_name], match) for match in matches]
    scan.status = "completed"
    record_audit_event(
        db,
        tenant_id=context.tenant_id,
        actor_id=context.actor_id,
        action="scan.completed",
        target_type="scan",
        target_id=scan.id,
        payload={"analyzer": analyzer, "dependency_count": len(dependencies), "finding_count": len(findings)},
    )
    db.commit()
    return RequirementsScanRead(
        scan_id=scan.id,
        dependency_count=len(dependencies),
        finding_count=len(findings),
        findings=[
            DependencyFindingRead(
                dependency_name=match.dependency.name,
                dependency_version=match.dependency.version,
                purl=match.dependency.purl,
                vulnerability_id=match.vulnerability.id,
                summary=match.vulnerability.summary,
                severity=match.vulnerability.severity,
                references=match.vulnerability.references,
            )
            for match in matches
        ],
    )


def _upsert_asset(db: Session, application_id: str, dependency: PythonDependency) -> Asset:
    asset = db.scalar(
        select(Asset).where(
            Asset.application_id == application_id,
            Asset.asset_type == "python_dependency",
            Asset.identifier == dependency.normalized_name,
        )
    )
    if asset is None:
        asset = Asset(
            application_id=application_id,
            asset_type="python_dependency",
            identifier=dependency.normalized_name,
            package_purl=dependency.purl,
            version=dependency.version,
        )
        db.add(asset)
        db.flush()
    else:
        asset.package_purl = dependency.purl
        asset.version = dependency.version
    return asset


def _get_application(db: Session, application_id: str, tenant_id: str) -> Application:
    application = db.scalar(
        select(Application).where(Application.id == application_id, Application.tenant_id == tenant_id)
    )
    if application is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application was not found.")
    return application


def _upsert_finding(db: Session, application_id: str, asset: Asset, match) -> Finding:
    finding = db.scalar(
        select(Finding).where(
            Finding.application_id == application_id,
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
    }
    if finding is None:
        finding = Finding(
            application_id=application_id,
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
    return finding
