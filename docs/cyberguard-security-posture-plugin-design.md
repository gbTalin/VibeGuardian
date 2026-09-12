# CyberGuard Security Posture Plugin — MVP Technical Design

## 1. Purpose

The Security Posture Plugin continuously evaluates authorized, published web applications and APIs against current vulnerability intelligence. It identifies applicable risk, gives safe remediation guidance, tracks decisions and fixes, and verifies outcomes through rescans.

This MVP is **read-only and non-destructive by default**. A `Passed` status means no actionable findings were detected within the scan scope and intelligence-freshness window; it never means the application is vulnerability-free.

## 2. MVP scope

### Included

- Ownership-verified public web applications and APIs.
- Python dependency manifests: `requirements.txt`, `poetry.lock`, `Pipfile.lock`, and CycloneDX or SPDX SBOMs.
- Optional container-image package inventories.
- Safe external checks: TLS certificates, security headers, DNS, redirects, and public endpoint availability.
- Vulnerability feeds: OSV, GitHub Security Advisories, CISA Known Exploited Vulnerabilities, NVD, and vendor advisories where available.
- Exa.ai for intelligence discovery/enrichment only; it is not authoritative proof of impact.
- Customer-controlled continuous intelligence monitoring, scheduled scans, release-triggered scans, and manual scans.
- Findings lifecycle, remediation guidance, rescans, audit history, and dashboard views.

### Explicitly excluded from MVP

- Exploit execution, denial-of-service testing, credential stuffing, or destructive checks.
- Automatic code, dependency, deployment, or cloud-configuration changes.
- Broad cloud write access.
- Unauthenticated scans of systems without recorded authorization.

## 3. High-level architecture

### Deployment decision

Build the MVP as a standalone, integration-ready Python service. CyberGuard will eventually host the plugin inside its existing Python backend, but the service must be buildable and testable independently until that backend is available.

The standalone boundary is an intentional compatibility layer, not a separate product. Keep all CyberGuard-specific dependencies behind adapters:

- **Identity adapter:** accepts signed service tokens in development; can later delegate user, role, and tenant resolution to CyberGuard's identity system.
- **Tenant/context adapter:** supplies `tenant_id`, `user_id`, roles, and application ownership without coupling core scan logic to CyberGuard's database schema.
- **Event adapter:** receives HTTP release events now; can later subscribe to CyberGuard's internal event bus.
- **UI adapter:** exposes a versioned REST API and stable response schemas for an interim standalone UI or future CyberGuard dashboard panels.
- **Secrets adapter:** uses a local development provider or managed secret store now; can later delegate to CyberGuard's secret-management facility.

Do not duplicate CyberGuard's eventual user directory, billing, or primary application inventory. In the standalone MVP, store only the minimum local application/asset records needed for scans, keyed by externally supplied tenant and application identifiers. Use versioned APIs and database migrations so integration changes are additive rather than a rewrite.

```text
CyberGuard UI / API (future host integration)
        |
        v
Security Posture API (standalone FastAPI service now)
        |
        +--> PostgreSQL: applications, assets, scans, findings, audit events
        +--> Encrypted secret store: integration credentials/test-account references
        +--> Redis queue
                    |
                    v
             Scan workers (Celery or Dramatiq)
                    |
     +--------------+---------------------------+
     |              |                           |
     v              v                           v
Dependency/SBOM  External-safe            Intelligence service
analyzer         analyzer          +--> authoritative source connectors
                                  +--> Exa Monitor webhooks
     |              |                           |
     +--------------+---------------------------+
                    |
                    v
            Correlation & risk engine
                    |
                    v
     Findings, remediation workflow, audit log, dashboard
```

### Recommended implementation stack

- Python 3.12+, FastAPI, Pydantic, SQLAlchemy, Alembic.
- PostgreSQL for durable application, finding, and audit data.
- Redis plus Celery or Dramatiq for asynchronous scan jobs.
- Object storage for encrypted scan artifacts and normalized feed snapshots.
- A managed secrets service or envelope-encrypted application secret store.
- Existing CyberGuard UI if available; otherwise, a React/Next.js dashboard backed by the FastAPI API.

For local development, provide Docker Compose configuration for the plugin API, worker, PostgreSQL, and Redis. Treat Docker Compose as a development harness only; production deployment should use CyberGuard's approved hosting and observability standards once integration begins.

## 4. Core data model

| Entity | Essential fields |
| --- | --- |
| `Application` | id, name, owner_id, environment, criticality, status, authorization_state |
| `Asset` | id, application_id, asset_type, identifier, public_url, package_purl, version, discovered_at |
| `Scan` | id, application_id, trigger, scope, status, started_at, completed_at, scanner_version, input_fingerprint |
| `MonitoringPolicy` | id, application_id, mode, enabled, schedule_expression, scan_scope, last_run_at, next_run_at |
| `IntelligenceEvent` | id, provider, provider_event_id, monitor_id, received_at, payload_hash, source_urls, processing_state |
| `VulnerabilityRecord` | canonical_id, aliases, source, source_url, affected_ranges, severity, fixed_versions, published_at, updated_at, confidence |
| `Finding` | id, application_id, asset_id, vulnerability_id, match_confidence, intrinsic_severity, adjusted_priority, state, evidence, first_seen_at, last_seen_at |
| `Remediation` | id, finding_id, recommended_action, official_reference, validation_steps, rollback_notes, generated_at |
| `RiskDecision` | id, finding_id, type, rationale, actor_id, expires_at |
| `AuditEvent` | id, actor_type, actor_id, action, target_type, target_id, timestamp, immutable_payload_hash |

Use PURLs and ecosystem-specific package names as the preferred dependency identifiers. Preserve raw source records and normalized fields so every correlation is explainable.

## 5. Scan lifecycle

1. A continuous-intelligence event, an authorized user, a customer schedule, or a release webhook creates a scan request.
2. The API validates ownership, scope, role, rate-limit policy, and whether authenticated testing is enabled.
3. For a continuous-intelligence event, the service verifies the Exa Monitor webhook secret, deduplicates the provider event, validates the intelligence against authoritative sources, and limits correlation to potentially affected assets.
4. A queued worker creates an immutable scan-input record and executes only approved analyzers.
5. Dependency, SBOM, external, and intelligence collectors produce evidence records.
6. The correlation engine creates or updates findings using exact package/version matches first, then bounded, reviewable heuristic matches.
7. The risk engine calculates priority and application status.
8. Remediation guidance is generated from official fixed-version/vendor sources wherever possible.
9. The scan result, findings changes, and all decisions are recorded in the audit trail.
10. A rescan compares current evidence with the prior completed scan; it resolves only findings whose original evidence is no longer present.

### Monitoring and scan modes

Customers choose one or more monitoring policies per application:

- **Continuous intelligence monitoring:** Exa Monitors and authoritative-feed updates trigger correlation when new intelligence arrives. This mode checks newly discovered intelligence against known assets and can create, update, or reopen a finding. It does not by itself perform intrusive testing.
- **Scheduled scans:** a customer-selected cadence performs the configured posture assessment, such as dependency/SBOM analysis and safe external checks.
- **Manual scans:** an authorized user runs the configured assessment on demand, typically after a release, dependency update, incident, or fix.
- **Release-triggered scans:** an authorized CI/CD integration submits a release event or updated artifact for reassessment.

Every scan records a trigger value (`continuous`, `scheduled`, `manual`, or `release`), the initiating user/service/monitor, scope, configuration version, and outcome. Schedules are tenant-defined and can be paused, edited, or deleted by an administrator.

## 6. Source reliability and correlation rules

Source precedence:

1. Vendor advisories, package maintainers, CISA KEV, and CVE/NVD records.
2. OSV and GitHub Security Advisories.
3. Trusted security-research publications.
4. Exa.ai-discovered reporting, used as enrichment or a review lead.

Exa Monitor design:

- Use reusable monitors organized by relevant technology, package ecosystem, vulnerability topic, or vendor advisory—not a separate public-web monitor for each customer application.
- Configure structured output that retains a title, source URL, publication date, identifiers, affected technologies, summary, and confidence cues.
- Receive completed runs at a final HTTPS webhook endpoint; validate the monitor secret, retain it only in encrypted storage, and use an internal delivery fingerprint to make webhook processing idempotent.
- Treat monitor results as leads. A result can increase priority or create `Needs Review`, but a confirmed vulnerability requires authoritative-source validation and asset-match evidence.

Correlation rules:

- Exact PURL/package ecosystem/version matches can create a confirmed finding.
- Version uncertainty, transitive dependency uncertainty, or unverified runtime reachability creates `Needs Review`.
- Keyword or framework similarity alone never creates a confirmed vulnerability.
- Conflicting records retain all source provenance and use the most conservative authoritative version range until reviewed.

## 7. Severity and application status

Intrinsic severity uses the best available CVSS score or authoritative severity. Environment-adjusted priority incorporates exploit maturity, CISA KEV membership, public exposure, asset criticality, data sensitivity, and compensating controls.

| Application status | Criteria |
| --- | --- |
| `Critical Action Required` | Confirmed critical risk, active exploitation, or CISA KEV exposure requiring prompt action |
| `Flagged` | One or more actionable high/critical findings, or accumulating unresolved material risk |
| `Needs Review` | Uncertain matches, incomplete scope, or findings requiring analyst triage |
| `Passed` | No confirmed/actionable findings in the stated scope and freshness window |

## 8. Finding workflow and remediation

Allowed finding states: `New`, `Triaged`, `In Progress`, `Mitigated`, `Resolved`, `Accepted Risk`, `False Positive`, and `Reopened`.

Every finding must show:

- Affected asset and exact observed version/configuration.
- Source citations and the evidence used for the match.
- Confidence level and intrinsic/adjusted severity.
- Official patch or fixed version when available.
- Safe mitigation, validation, compatibility-test, and rollback guidance.
- Prior scan comparison and complete state history.

False-positive and accepted-risk decisions require an authorized actor, written rationale, timestamp, and optional expiry. Any changed dependency, changed source intelligence, or changed scope re-evaluates the suppression.

## 9. Permissions and security boundaries

| Role | Permissions |
| --- | --- |
| Viewer | View authorized applications, findings, and reports |
| Analyst | Trigger approved scans; triage findings; propose suppressions |
| Remediation Owner | Update remediation status and initiate rescans |
| Administrator | Manage applications, integrations, authorizations, roles, and retention |
| Integration Service | Minimum API scope needed to submit artifacts or release events |

- Prove domain ownership before external scanning, such as a DNS TXT record, signed token file, or approved CyberGuard integration.
- Require explicit authorization to enable authenticated testing; use dedicated test accounts and references to secrets, never plaintext credentials in logs.
- Enforce egress allowlists, per-target concurrency limits, request budgets, and retries with backoff.
- Redact secrets, access tokens, cookies, authorization headers, personal data, and proprietary source excerpts from findings and logs.
- Encrypt artifacts and integration secrets at rest and in transit. Apply retention/deletion policies per tenant.

## 10. API surface

```text
POST   /v1/applications
GET    /v1/applications/{application_id}
POST   /v1/applications/{application_id}/authorization/verify
POST   /v1/applications/{application_id}/scans
GET    /v1/applications/{application_id}/scans
GET    /v1/applications/{application_id}/monitoring-policies
POST   /v1/applications/{application_id}/monitoring-policies
PATCH  /v1/monitoring-policies/{policy_id}
DELETE /v1/monitoring-policies/{policy_id}
POST   /v1/webhooks/exa/monitors
GET    /v1/scans/{scan_id}
GET    /v1/applications/{application_id}/findings
GET    /v1/findings/{finding_id}
PATCH  /v1/findings/{finding_id}
POST   /v1/findings/{finding_id}/risk-decisions
POST   /v1/integrations/release-events
GET    /v1/applications/{application_id}/audit-events
GET    /v1/applications/{application_id}/posture
```

`POST /scans` accepts an explicitly bounded scope: target URLs, supplied manifests/SBOM artifact references, analyzer selection, and optional authenticated test profile. It must reject scopes beyond the recorded authorization.

Monitoring-policy creation accepts a mode (`continuous`, `scheduled`, or both), a bounded scan scope, and—when scheduled—a validated schedule expression and timezone. Webhook callers cannot choose an application scope; CyberGuard resolves it from the stored monitor/technology mapping and authorization records.

## 11. Dashboard views

1. **Posture overview:** application status, risk trend, last successful scan, scope, and intelligence freshness.
2. **Prioritized findings:** filters by severity, state, confidence, source, asset, owner, and age.
3. **Finding detail:** evidence, citations, risk explanation, remediation, history, and rescan result.
4. **Scan history:** status, inputs, changed findings, errors, and comparison with the prior scan.
5. **Asset inventory:** public targets, packages, container artifacts, ownership, and last-observed state.
6. **Audit log:** searchable, append-only records of scans, decisions, permissions, and integrations.
7. **Monitoring settings:** opt-in continuous monitoring, scheduled scan cadence/timezone, scan scope, current monitor health, and manual-run control.

## 12. Phased implementation

### Phase 0 — Foundation

- Establish tenant isolation, RBAC, application authorization, audit-event hashing, secrets redaction, migrations, and background job infrastructure.

### Phase 1 — Supply-chain MVP

- Parse Python manifests/SBOMs.
- Implement OSV and GitHub Advisory connectors.
- Correlate exact package/version matches.
- Deliver findings, safe remediation guidance, manual scans, scheduling policies, and dashboard basics.

### Phase 2 — Production posture

- Add domain ownership validation and safe TLS/header/DNS checks.
- Add CISA KEV and NVD/vendor intelligence.
- Implement Exa Monitor webhook ingestion, adjusted priority, rescans, diffs, and source-freshness reporting.

### Phase 3 — Operational integrations

- Add release webhooks, container image inventory, read-only deployment metadata, assigned ownership, report exports, and dedicated test-account authenticated checks.

## 13. Acceptance criteria for MVP

- A tenant can prove authorization for an application and launch a bounded scan.
- A tenant can enable/disable continuous monitoring, create a scheduled scan policy with a defined timezone, and start a manual scan.
- The plugin parses a Python manifest or SBOM and identifies a known vulnerable dependency using source-cited evidence.
- An Exa Monitor webhook is authenticated, deduplicated, retained as an intelligence event, and cannot create a confirmed finding without authoritative-source validation and asset-match evidence.
- A finding shows a confidence level, intrinsic severity, environment-adjusted priority, and safe remediation/validation instructions.
- A scan of a verified public URL performs only safe, rate-limited TLS, header, DNS, and availability checks.
- Analysts can triage findings; accepted-risk and false-positive decisions are attributed and auditable.
- A rescan updates findings based on the original evidence and retains the complete history.
- The dashboard displays posture, active findings, scan history/diffs, source freshness, and audit events.
- Automated tests demonstrate tenant isolation, authorization enforcement, secret redaction, scope enforcement, and no network actions outside approved targets.

## 14. First engineering tickets

1. Scaffold an integration-ready FastAPI service, PostgreSQL migrations, Redis worker, development Docker Compose harness, health checks, and versioned API routing.
2. Define identity, tenant/context, event, UI, and secrets adapter interfaces; implement safe development adapters without duplicating CyberGuard's eventual user/application systems.
3. Implement local `Application`, `Asset`, `Scan`, `Finding`, and `AuditEvent` schemas and repositories keyed to external tenant/application identifiers.
4. Add `MonitoringPolicy` and `IntelligenceEvent` schemas, plus manual/scheduled scan dispatch and scan-trigger audit fields.
5. Build manifest/SBOM ingestion for `requirements.txt`, `poetry.lock`, `Pipfile.lock`, CycloneDX, and SPDX.
6. Implement OSV and GHSA normalized connectors and exact package-version correlation.
7. Add Exa Monitor provisioning/webhook ingestion, webhook-secret validation, idempotent event processing, and authoritative-source validation.
8. Add domain-ownership verification, bounded scan-scope validation, finding state transitions, immutable audit events, and rescan comparison.
9. Create posture overview, findings list/detail, scan-history, and monitoring-settings dashboard screens.
10. Add tests for adapters, authorization, schedules, source normalization, webhook authentication/deduplication, version matching, redaction, and finding lifecycle.
