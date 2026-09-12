# CyberGuard Threat Intelligence Plugin

An integration-ready standalone Python service for CyberGuard's production security posture plugin. It is intentionally structured so CyberGuard's future identity, tenant, event, UI, and secret-management systems can replace development adapters without changing scan logic.

## Current foundation

- Versioned FastAPI API and health endpoint.
- Tenant and actor context boundary for local development.
- Application registration and audit-event recording.
- Exact-version Python requirements, Poetry, Pipenv, CycloneDX, and SPDX scanning with OSV correlation.
- Customer-controlled continuous and scheduled monitoring policies.
- Authenticated, idempotent Exa Monitor webhook intake that queues completed monitor runs for authoritative validation.
- Celery worker and scheduler configuration that dispatches due scheduled scans as queued jobs.
- Signed release-artifact intake for future CyberGuard deployment and CI/CD events.
- SSRF-resistant foundation for safe public HTTPS posture checks.
- SQLAlchemy data model for applications, assets, scans, findings, monitoring policies, intelligence events, and audit records.
- Local SQLite default; Docker Compose development services for PostgreSQL and Redis.

## Local development

Copy `.env.example` to `.env`, then install the project with your preferred Python environment manager. Run the API with:

```sh
uvicorn cg_threat_intel.main:app --reload
```

The development context requires two headers on tenant-scoped routes:

```text
X-CG-Tenant-ID: local-tenant
X-CG-Actor-ID: local-admin
```

These headers are a development-only adapter. Production CyberGuard integration will provide authenticated tenant and actor context instead.

## API currently available

- `GET /health`
- `POST /v1/applications`
- `GET /v1/applications`
- `POST /v1/applications/{application_id}/scans/requirements`
- `POST /v1/applications/{application_id}/scans/dependencies`
- `POST` / `GET /v1/applications/{application_id}/monitoring-policies`
- `PATCH /v1/monitoring-policies/{policy_id}`
- `POST /v1/webhooks/exa/monitors`
- `POST /v1/integrations/release-events`

API documentation is available at `/docs` while the service is running.

The initial dependency scanner accepts exact versions only. This is deliberate: unpinned dependencies cannot support a reliable version-vulnerability decision. The normalized dependency endpoint supports `requirements`, `poetry_lock`, `pipfile_lock`, `cyclonedx_json`, and `spdx_json` artifacts.

Configure `CG_EXA_WEBHOOK_SECRET` from the one-time secret returned when an Exa Monitor is created. The service verifies the timestamped `Exa-Signature` HMAC on the exact request body and deduplicates deliveries before storing a minimal intelligence-event record. A received Exa event is an intelligence lead only; authoritative validation and asset correlation remain a separate step.

The Docker development stack includes `api`, `worker`, and `scheduler` services. The scheduler checks due policies once per minute and creates a queued scan for each policy's explicitly stored scope. Worker execution for each artifact type is added incrementally; the current immediate scanner is the manual requirements scan.

`POST /v1/integrations/release-events` uses a timestamped HMAC header named `X-CG-Release-Signature`. It accepts a tenant/application identifier, release ID, event ID, normalized artifact type, and artifact content. The raw artifact is analyzed immediately and never persisted; the service retains only its SHA-256 fingerprint, metadata, resulting scan ID, and audit event.
