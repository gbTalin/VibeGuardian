# Guardian-Unit-Penetration-Testing Agent

## Executive decision

Guardian-Unit-Penetration-Testing Agent is a local-first security release gate for applications created with AI coding tools and vibe-coding platforms. It combines deterministic source and deployment-configuration analysis with a tightly bounded, explicitly authorized probe of a running application. It produces a reproducible `PASS`, `WARN`, `HOLD`, or `BLOCK` decision and a plain-language evidence pack before deployment.

The product will not claim to replace a professional penetration test. Automated static checks and a non-destructive HTTP probe cannot validate every authorization path, business-logic flaw, runtime cloud control, or post-authentication behavior. The product name identifies the specialist agent; the product description will consistently call it a security release gate with authorized probing.

The implementation will reuse the existing Rampart scanner core rather than rebuild generic SAST capabilities. Rampart already contains deterministic scanners for secrets, AI-generated code defects, agent risks, dependencies, CI, IaC, application code, and public surface checks, along with redaction, SARIF, MCP, stable fingerprints, and test fixtures. The new work will harden the live probe, add a release-policy layer, package the engine for multiple agent platforms, and introduce stable contracts for a future real-time threat-intelligence plugin.

## Product identity

| Surface | Value |
|---|---|
| Display name | `Guardian-Unit-Penetration-Testing Agent` |
| Plugin and package identifier | `guardian-unit-penetration-testing-agent` |
| CLI executable | `guardian-unit` |
| Configuration directory | `.guardian-unit/` in a repository |
| User configuration directory | `~/.guardian-unit/`, used only when explicitly selected |
| Initial version | `0.1.0` |
| License | Apache-2.0 for original Guardian-Unit code and inherited Rampart code |

The normalized lower-case plugin identifier satisfies Codex plugin naming constraints while the interface metadata preserves the requested display name.

## Target customer and job

The primary customer is a non-technical builder using AI to create and deploy an application without a dedicated application-security team. The product performs one specific job:

> Before code is deployed, identify high-confidence security blockers in the repository and approved live target, explain the plausible attacker path in plain language, provide a concrete fix and verification step, and prevent the release when evidence meets the configured blocking policy.

The first commercial wedge is not broad vulnerability scanning. Existing platforms already provide generic SAST, SCA, secret scanning, and AI-code guardrails. Guardian-Unit differentiates through:

- High-confidence checks for AI-scaffold failure modes such as client-exposed privileged keys, missing server-side authorization, permissive Supabase policies, and unsafe model-to-tool paths.
- A single release decision spanning source, CI, IaC, agent configuration, and an authorized live target.
- Clear separation of verified findings, heuristic signals, incomplete coverage, and unproven controls.
- Stable evidence receipts that survive integration across coding agents and CI systems.
- Local execution with no source-code upload or telemetry by default.
- A future signed intelligence channel that improves prioritization without allowing a feed to rewrite the executable gate.

Lovable already advertises RLS, database, code-security, and dependency checks in its native Security view.^1 Guardian-Unit will therefore integrate with Lovable as an independent evidence and GitHub deployment gate, not market itself as the first security scanner available to Lovable users.

## Goals

Version 0.1.0 will:

1. Scan a local repository without an account, API key, model, telemetry, or network connection.
2. Detect high-confidence source, secret, dependency-manifest, CI, IaC, and AI-agent risks.
3. Probe one exactly authorized running origin with a bounded, non-authenticated request plan.
4. Produce terminal, Markdown, JSON, SARIF 2.1.0, and release-receipt output.
5. Expose the same gate through a CLI and local MCP server.
6. Package adapters for Codex, Claude Code, VS Code and GitHub Copilot, Google Antigravity, Cursor, Windsurf, Lovable, and GitHub Actions.
7. Offer a project-local installer that detects supported platforms and writes only the requested integration files.
8. Define and exercise the intelligence-provider, pack, cache, freshness, and candidate-threat contracts required by the future threat-intelligence plugin.
9. Fail safely when authorization, evidence, scanner execution, or intelligence freshness is incomplete.
10. Prove behavior through unit, integration, vulnerable-fixture, active-probe, packaging, and clean-install tests.

## Non-goals

Version 0.1.0 will not:

- Perform exploitation, credential attacks, password spraying, phishing, persistence, lateral movement, destructive testing, data extraction, denial of service, port scanning, subdomain enumeration, or cloud metadata probing.
- Crawl an application, submit forms, authenticate, test cross-tenant access, or attempt business-logic attacks.
- Automatically fix code or rotate secrets.
- Claim that the absence of findings proves an application is secure.
- Run ZAP, Semgrep, CodeQL, Trivy, Gitleaks, OSV-Scanner, or other third-party engines as mandatory dependencies.
- Depend on an LLM for a deploy decision.
- Operate a hosted control plane, billing system, shared customer corpus, or public threat feed.
- Publish to npm, GitHub, or external plugin marketplaces without an authenticated destination explicitly supplied by the owner.
- Allow downloaded intelligence to execute code or silently change deployment authorization, policy thresholds, or stable blocking behavior.

## Alternatives considered

### Approach A: Extend Rampart and add thin adapters

This is the selected approach. It retains a tested, zero-runtime-dependency Node engine and adds only the new release-gate, probe-safety, intelligence-contract, installer, and integration layers. It is the only approach compatible with the one-hour working-version target without substituting a shallow demonstration for a functioning scanner.

Advantages:

- Existing deterministic rules, evidence model, redaction, SARIF, MCP, and fixtures.
- No mandatory external account, network request, or scanner download.
- Original rules avoid Semgrep Community Rules redistribution restrictions.^2
- One engine means every integration receives the same decision and evidence.

Risks:

- Existing rules remain pattern and flow heuristics rather than full language-specific semantic analysis.
- The inherited live surface scanner requires hardening before it can safely run as an automatic production probe.
- Node 22.18 or later is required for the current native TypeScript and SQLite approach.

### Approach B: Orchestrate third-party scanners

This would wrap tools such as Semgrep, Trivy, Gitleaks, OSV-Scanner, ZAP, and vendor SaaS CLIs. It offers broader coverage but introduces downloads, databases, authentication, licensing review, inconsistent output, platform dependencies, and long runtimes. It is appropriate for optional Phase 2 adapters, not the required v1 execution path.

### Approach C: Hosted security service

A hosted service could centralize policy, intelligence, dashboards, and analytics. It conflicts with the local-first privacy wedge, creates a new high-value source-code repository, and requires authentication, tenancy, storage, billing, and operational controls. It is explicitly deferred.

## System architecture

```text
Agent or developer requests deployment
                 |
                 v
        Platform-specific adapter
     hook, skill, command, or workflow
                 |
                 v
      guardian-unit gate <repository>
       /             |              \
      v              v               v
Static scanners  Authorized probe  Intelligence cache
      \              |               /
       \             |              /
        v            v             v
         Evidence normalization and policy
                      |
          +-----------+-----------+
          |           |           |
        reports      receipt     exit code
          |           |           |
          +-----------+-----------+
                      |
          GitHub Actions required check
                      |
          protected deployment environment
```

The CLI is the product contract. Platform plugins improve discovery and intercept agent-issued deployment commands where the host supports hooks. GitHub Actions and protected deployment environments remain the authoritative cross-platform enforcement boundary because local hooks, skills, rules, and MCP tools can be disabled or bypassed.

## Components

### Scanner engine

The scanner engine walks an explicitly selected repository root and dispatches applicable scanner families. Each scanner returns normalized findings rather than printing output or deciding whether a release passes.

The initial families are:

- Secrets and credential exposure
- AI-generated application defects
- AI-agent, model, prompt, and MCP risks
- Dependencies and supply-chain configuration
- CI/CD workflow security
- Infrastructure-as-code and container configuration
- Application source-to-sink patterns
- Authorized public-surface observations

All deterministic findings retain their original provenance. An optional model or specialist-agent review may add explanation or a separate assessment, but it cannot delete, downgrade, or silently upgrade a deterministic finding.

### Release-policy engine

The policy engine consumes normalized findings and coverage facts. It does not inspect files or perform network requests. Its output is one of four outcomes:

| Outcome | Definition | Default CI behavior |
|---|---|---|
| `PASS` | Required checks completed and no configured blocking condition was found | Continue |
| `WARN` | Checks completed with non-blocking hardening findings or unproven signals | Continue and annotate |
| `HOLD` | Required evidence is incomplete, stale, unavailable, or operationally failed | Stop pending review |
| `BLOCK` | A verified or high-confidence condition breaches release policy | Deny deployment |

Default blocking conditions include exposed live credentials, high-confidence dangerous source-to-sink paths, unsafe deployment configuration with material impact, invalid TLS for an approved production target, and confirmed sensitive public exposure.

Missing CSP, HSTS, defensive headers, `security.txt`, or similar hardening observations are warnings unless customer policy explicitly elevates them. A scanner-only ambiguous match begins as `UNPROVEN` and cannot block by itself.

### Exit-code contract

The new `gate` command uses a stable exit-code contract distinct from the inherited `scan --ci` behavior:

| Exit | Meaning |
|---:|---|
| `0` | `PASS` |
| `1` | `BLOCK` |
| `2` | `WARN` |
| `3` | `HOLD` because required evidence is incomplete |
| `4` | `REFUSED` because authorization or target validation failed |
| `5` | Internal tool or configuration error |

The GitHub adapter may be configured to allow exit `2`; exits `1`, `3`, `4`, and `5` fail the required check by default. Local interactive adapters show the same distinction rather than flattening all nonzero exits into a generic error.

## Authorized live probe

### Authorization record

No network request may begin until Guardian-Unit has loaded and validated a project-local authorization record. The default path is `.guardian-unit/targets.json`.

```json
{
  "schemaVersion": 1,
  "targets": [
    {
      "origin": "https://app.example.com",
      "environment": "production",
      "owner": "security@example.com",
      "approvedAt": "2026-09-12T18:00:00Z",
      "expiresAt": "2026-10-12T18:00:00Z",
      "maxRequests": 5,
      "maxRedirects": 2,
      "connectTimeoutMs": 3000,
      "totalTimeoutMs": 10000,
      "requestsPerSecond": 1,
      "allowCorsObservation": true,
      "approvedExtraPaths": []
    }
  ]
}
```

The record is intended to be reviewed in version control. The receipt stores its SHA-256 digest. A future enterprise policy service may sign authorization records, but v1 does not invent a signing authority without key-management infrastructure.

### Default request plan

After authorization, a production probe performs at most five unauthenticated requests:

1. `GET /` over HTTPS.
2. `GET /` over HTTP solely to observe whether it redirects to the authorized HTTPS origin.
3. `GET /.well-known/security.txt`.
4. `GET /robots.txt`.
5. `OPTIONS /` with a benign `Origin: https://probe.invalid` only when CORS observation is authorized.

This is active network traffic but not exploit testing. The probe does not crawl, follow page links, submit forms, authenticate, retain response bodies, or send attack payloads. ZAP Baseline is deferred as an optional staging-only integration; the official ZAP documentation describes it as non-attacking but notes that it spiders the target by default.^3

For staging, `approvedExtraPaths` permits a small fixed list chosen by the owner. Production defaults to an empty list. The engine will not derive targets or paths from source files, third-party intelligence, redirects, robots files, sitemaps, or model output.

### Collected observations

The probe records only the evidence required for policy decisions:

- TLS connection success, certificate validity, hostname match, and negotiated protocol where available.
- Status code and same-origin redirect chain.
- HSTS, CSP, MIME-sniffing, framing, referrer, permissions, cache, and cross-origin headers.
- Cookie names and security attributes; cookie values are discarded before storage or output.
- Presence and basic format of `security.txt` and `robots.txt`.
- Length-capped signatures of verbose root-page errors or debug output, without persisting the response body.

OWASP recommends relevant HTTP response headers and secure cookie attributes as defense-in-depth controls.^4,5 Absence of `security.txt` or `robots.txt` is informational. A robots file is not an authorization mechanism and never expands scan scope.^6,7

### Target and SSRF safety

The probe will:

- Accept only `http` or `https`, with `https` mandatory outside explicit local mode.
- Reject user-info URLs, fragments, unsupported ports, wildcard hosts, ambiguous encodings, and IP literals outside local mode.
- Match the exact authorized scheme, hostname, and effective port.
- Resolve both A and AAAA records and reject private, link-local, carrier-grade NAT, multicast, reserved, and cloud-metadata destinations for staging and production.
- Permit loopback only when the authorization record declares `environment: local` and names `localhost`, `127.0.0.1`, or `::1` exactly.
- Pin each connection to a validated address while preserving the approved hostname for SNI and the Host header.
- Revalidate every redirect and never follow a cross-origin redirect.
- Disable proxy environment inheritance.
- Enforce request, redirect, time, header, and response-size budgets.
- Return `HOLD` or `REFUSED`, never `PASS`, when safety validation or coverage is incomplete.

These controls follow OWASP guidance to validate schemes, domains, and resolved addresses; use exact allowlists; and constrain redirects when preventing SSRF.^8

## Evidence and reporting

Every finding includes:

- Stable ID and fingerprint
- Severity and confidence
- Deterministic, heuristic, intelligence, or agent-review provenance
- Repository-relative file and line or authorized origin
- Redacted evidence
- Preconditions and plausible attack path
- Business impact in plain language
- Concrete remediation steps
- Verification or regression-test requirement
- Relevant CWE, OWASP, and compliance mappings when supportable
- Explicit limitations and untested controls

The release receipt is canonical JSON with deterministic field ordering and includes:

```text
receipt schema version
Guardian-Unit runtime version and digest
ruleset version and digest
release-policy version and digest
intelligence-pack sequence, digest, and freshness state
repository commit and dirty-worktree indicator
authorization-record digest and normalized target
scan start and finish timestamps
scanner coverage and skipped checks
finding fingerprints and dispositions
final outcome and exit code
receipt SHA-256
```

SARIF output enables code-scanning ingestion while Markdown provides the non-technical report. GitHub accepts SARIF 2.1.0 for code-scanning results.^9 Secrets, cookie values, authorization headers, raw environment values, and complete response bodies never enter reports, receipts, prompts, or logs.

## Platform integration model

### Authoritative deployment enforcement

The GitHub Actions adapter runs the same local CLI against the checked-out commit. It uploads SARIF and the release receipt, then exposes a required status check. Production deployments should use a protected environment or deployment protection rule so the deployment job cannot begin without the gate result.^10

The initial repository contains a local composite action and workflow template. A public reusable Action can be added only after the repository has an immutable release commit. External action references will be pinned to full commit SHAs; GitHub identifies a full-length commit SHA as the immutable release reference for third-party actions.^11

### Agent and IDE adapters

| Platform | Package | Local interception | Limitation |
|---|---|---|---|
| Codex | Plugin with Skill, MCP, and lifecycle hook | `PreToolUse` checks recognized deploy commands | Plugins are unsupported in the Codex IDE extension; CI remains authoritative.^12,13 |
| Claude Code | Plugin with Skill, MCP, and hook | `PreToolUse` can deny matched tool calls | Only Claude-issued actions are covered.^14 |
| VS Code | Agent Plugin with Copilot metadata, MCP, and hook | Preview `PreToolUse` hook | Preview and agent-scoped; manual terminal actions bypass it.^15,16 |
| GitHub Copilot | Plugin/custom agent with `preToolUse` | Supported agent surfaces can deny calls | Host and cloud-agent capabilities vary; CI remains authoritative.^17,18 |
| Google Antigravity | Native plugin with Skill, rules, MCP, and hook | `PreToolUse` returns allow, deny, or ask | Browser, terminal, and other deployment paths bypass it.^19,20 |
| Cursor | Rules, command, Skill, and MCP | Guided preflight only | No official mandatory deploy interceptor was established.^21 |
| Windsurf | Skill, MCP, and workflow | Guided preflight only | MCP availability is not an enforcement boundary.^22 |
| Lovable | Workspace Skill and GitHub synchronization | No documented third-party native-publish block | GitHub-driven deployment can be gated; native Publish remains outside control.^1,23 |
| Other agents | `AGENTS.md`, portable Skill, CLI, and MCP | Host-dependent | Unverified hosts are convenience integrations only. |

Hook matching will recognize a narrow, testable list of deployment commands and MCP deployment tools. It will never attempt to classify every shell command as deployment-related. Each hook reports the exact command it matched and lets the CLI make the decision.

### MCP contract

The MCP server is local stdio by default and exposes non-destructive tools:

- `guardian_security_scan`
- `guardian_release_gate`
- `guardian_explain_finding`
- `guardian_get_receipt`
- `guardian_intelligence_status`

MCP mode does not expand authorization. Network access remains disabled unless the requested gate references a valid authorization record. No tool performs deployment, modification, secret rotation, or exploit execution.

## One-command installer

The project-local installer supports:

```bash
npx guardian-unit-penetration-testing-agent@0.1.0 init --all \
  --target https://app.example.com \
  --environment production \
  --owner security@example.com
```

Until publication, the verified npm tarball is invoked directly:

```bash
npx ./dist/guardian-unit-penetration-testing-agent-0.1.0.tgz init --all \
  --target https://app.example.com \
  --environment production \
  --owner security@example.com
```

The installer detects repository markers and creates only project-local files. `--all` installs every applicable adapter found in the repository plus GitHub Actions; explicit `--platform` values restrict the set. Existing files are merged conservatively or left unchanged with a precise conflict report. Global installation requires a separate explicit `--global` flag and is not used in automated tests.

The installer is idempotent. A second run with identical arguments produces no content changes. It also supports `doctor`, `check`, and `uninstall --dry-run`. Actual uninstall removes only files and marked blocks created by the installer.

## Threat-intelligence extension architecture

### Separation of responsibilities

The future `guardian-unit-threat-intelligence` plugin retrieves, validates, normalizes, and installs data packs. It cannot run a scan, change authorization, invoke deployment, execute remediation, or write executable plugin files.

The penetration-testing agent consumes a local, read-only intelligence-cache interface. This makes the gate useful offline and prevents a feed outage from mutating scanner behavior mid-run.

### Provider contract

```ts
interface IntelligenceProvider {
  descriptor(): ProviderDescriptor;
  fetchSince(cursor: string | null, signal: AbortSignal): Promise<ProviderBatch>;
  validate(batch: ProviderBatch): ValidationResult;
  normalize(batch: ProviderBatch): IntelligenceRecord[];
}

interface ProviderDescriptor {
  id: string;
  kind: "vulnerability" | "exploit-priority" | "applicability" | "cti";
  transport: "bundle" | "file" | "https" | "taxii";
  schemaVersion: string;
  termsUrl?: string;
  attribution?: string;
}
```

The stable record preserves provider identity instead of flattening distinct claims:

```ts
interface IntelligenceRecord {
  recordId: string;
  providerId: string;
  aliases: string[];
  affected: {
    ecosystems?: string[];
    packageUrls?: string[];
    versions?: unknown;
    cpes?: string[];
  };
  severityClaims: SourceScore[];
  knownExploited?: SourceClaim<boolean>;
  exploitProbability?: SourceClaim<number>;
  applicability?: "known_affected" | "known_not_affected" | "fixed" | "under_investigation";
  publishedAt?: string;
  modifiedAt?: string;
  sourceUrl: string;
  contentDigest: string;
  marking?: string;
}
```

CISA KEV expresses observed exploitation and should influence prioritization, not prove that a specific customer deployment is exploitable.^24 EPSS estimates the probability of exploitation in the next 30 days and is neither severity nor proof.^25 OSV is the preferred package/version matcher and supports downloadable ecosystem data and incremental modified-record lists.^26 STIX 2.1 and TAXII 2.1 are enterprise interchange and transport standards, not trusted universal feeds.^27,28

### Pack manifest

```json
{
  "schemaVersion": 1,
  "packId": "guardian-unit/intel/core",
  "sequence": 42,
  "issuedAt": "2026-09-12T18:00:00Z",
  "expiresAt": "2026-09-13T18:00:00Z",
  "minimumRuntime": "0.1.0",
  "channel": "stable",
  "recordsDigest": "sha256:...",
  "recordCount": 1200,
  "sources": [],
  "signature": {
    "scheme": "sigstore-bundle",
    "identity": "guardian-unit-release@example.com",
    "bundle": "pack.sigstore.json"
  }
}
```

Version 0.1.0 implements parsing, schema validation, digest verification, atomic local installation, freshness evaluation, and last-known-good fallback for project-provided packs. It does not fetch a remote pack or claim signature verification before the trust infrastructure exists.

### Secure remote updates

Future remote distribution uses two separately versioned supply chains:

1. Frequent signed data-only intelligence packs.
2. Deliberately released executable runtime, parser, adapter, and rule packages.

The remote update system will adopt TUF concepts for trusted root metadata, delegated roles, threshold signatures, target hashes and lengths, monotonically increasing versions, and metadata expiration. TUF is designed to resist rollback, freeze, mix-and-match, and arbitrary-package attacks.^29

Sigstore bundles will bind artifact digests to an expected producer identity and provide transparency evidence that can be verified offline when the bundle contains the required material.^30 SLSA/in-toto provenance will identify the approved source revision, build system, and inputs used to create an executable or stable rule release.^31,32

The client retains its highest accepted sequence and last-known-good pack. It rejects lower sequences, expired metadata, signature failures, digest mismatches, schema incompatibility, and unexpected publisher identities. A failed update never replaces the valid cache. A configured maximum-staleness breach produces `HOLD`, not a misleading current result.

### Data versus behavior

| Update class | Automatic stable installation | Permitted effect |
|---|---:|---|
| CVE, CWE, package ranges, hashes, references, source attribution | Yes after validation | Enrichment and matching |
| CISA KEV and EPSS values | Yes after validation | Prioritization |
| Passive indicators | Yes after validation | Non-blocking annotation by default |
| Signed vendor VEX/CSAF | Yes as an assertion | `not_affected_asserted`; never delete the original finding |
| New or changed detection rule | No | Candidate/canary only until promoted |
| Severity or release-policy change | No | Human change control and signed stable release |
| Parser, script, prompt, model, container, WASM, hook, or MCP configuration | Never through the data channel | Separate executable release |
| Authorization scope, target, rate limit, or credentials | Never | Customer-controlled only |

All text from external intelligence is display-only untrusted data. It is length-capped, escaped, and excluded from system instructions, shell commands, URLs to fetch, remediation execution, and model tool configuration.

## Continuous discovery and candidate promotion

When a scan produces a novel, non-duplicate pattern, Guardian-Unit automatically creates a local candidate record containing:

- Candidate ID and stable fingerprint
- Redacted evidence features
- Scanner and ruleset versions
- Repository-relative location class
- Preconditions and observed sink class
- Positive synthetic fixture proposal
- Negative synthetic fixture proposal
- Confidence and evidence provenance
- Local creation and last-observed timestamps
- Promotion state

The candidate is immediately available as a non-blocking canary observation in that repository. It cannot change target scope, send network traffic, execute code, alter severity, or block deployment.

If a customer explicitly enables contribution, the system may submit only a redacted fingerprint and generalized pattern. Source snippets, repository identity, URLs, secrets, customer names, and raw responses remain local. The central promotion flow is:

```text
candidate ingestion
       |
deduplication and source corroboration
       |
data-only declarative rule proposal
       |
isolated positive, negative, adversarial, and regression tests
       |
non-blocking canary channel
       |
false-positive and performance gates
       |
two-person approval and signed stable pack
```

Candidate rules use a constrained data-only DSL. They receive no filesystem, environment, network, shell, dynamic import, `eval`, code-generation, LLM, or tool-call capability. Regexes have complexity limits and bounded input. A future rules engine may use a non-backtracking implementation, but v1 records the contract without introducing a new parser.

## Versioning and compatibility

- Runtime, plugin, adapter, policy schema, receipt schema, intelligence schema, and ruleset have independent semantic versions.
- Every adapter declares compatible runtime and schema ranges.
- CI invokes an exact runtime version or immutable artifact digest, never a mutable `latest` tag.
- GitHub Actions references are pinned to full commit SHAs.
- Threat packs use monotonically increasing sequence numbers in addition to schema versions.
- Stable runtime and rule releases retain N-1 schema compatibility for rollback.
- Canary intelligence can annotate but cannot block.
- Executable upgrades are introduced through a reviewed pull request or managed-device rollout, not a silent marketplace refresh.

SLSA provenance and verification are meaningful only when the consumer verifies the artifact against a preconfigured trust root and expected builder.^31 The release receipt therefore records both the runtime digest and intelligence-pack digest so the deployment decision can be reproduced later.

## Privacy and trust boundaries

### Default posture

- Static scanning remains local.
- No telemetry exists.
- Network is off unless a live target is explicitly authorized or a future intelligence provider is explicitly enabled.
- The live probe sends no cookies, credentials, tokens, forms, or attack payloads.
- The future intelligence updater downloads data; it does not upload source or dependency inventory by default.
- Optional online package queries require separate network consent and clearly state which package names and versions leave the device.
- Model-based review is optional and must state whether selected redacted excerpts are sent to a hosted provider.

### Principal threats to Guardian-Unit

| Threat | Control |
|---|---|
| Malicious repository instructions manipulate the agent | Deterministic engine ignores prompt-like content; external text remains untrusted data |
| Scanner leaks a secret into reports | Central redaction before persistence, output, prompt, or log |
| Authorized URL redirects to an internal service | Exact-origin redirect validation and address pinning |
| DNS rebinding reaches a private address | A/AAAA validation immediately before pinned connection |
| Threat feed becomes remote code execution | Data-only schema, no executable fields, signed packs, constrained parser |
| Compromised update repository serves old or mixed artifacts | TUF-style version, expiry, snapshot, and digest verification |
| Compromised publisher silently signs malicious updates | Threshold roles, Sigstore identity policy, transparency monitoring, canary release |
| User disables an IDE plugin | GitHub required check and protected deployment remain authoritative |
| No network or feed outage produces a false pass | Explicit freshness state and configurable `HOLD` on stale required intelligence |
| Noisy candidate rule blocks customers | Candidate and canary rules are non-blocking; stable promotion requires tests and approval |

## Error handling

- Invalid source configuration produces exit `5` with a precise local error and no scan claim.
- Missing or expired target authorization produces exit `4` before network activity.
- DNS, TLS, timeout, redirect, response-budget, or rate-limit interruption produces `HOLD` and preserves partial coverage facts.
- A scanner failure does not erase results from successful scanners; required-scanner failure produces `HOLD`.
- Report-write failure does not change evidence already in memory but prevents a release receipt from being considered complete.
- Intelligence parse, signature, digest, expiry, or schema failure keeps the last-known-good cache and marks the attempted update rejected.
- An unavailable optional model produces a warning and leaves deterministic findings unchanged.
- Hook adapters surface Guardian-Unit output without silently substituting an allow decision after timeout.

## Implementation scope for version 0.1.0

The implementation will create a new repository-local product based on the Rampart source, excluding its `node_modules`, historical strategy documents, and unrelated generated artifacts. Work is divided into independent modules:

1. Core port and product rename.
2. Gate policy, outcome, receipt, and exit-code contract.
3. Authorized HTTP/TLS probe and target validation.
4. Intelligence contracts, local pack cache, candidate registry, and freshness reporting.
5. Codex plugin and MCP/Skill/hook package.
6. Claude Code, VS Code/Copilot, Antigravity, Cursor, Windsurf, and Lovable adapters.
7. GitHub composite Action and workflow template.
8. Project-local platform detector and installer.
9. Documentation and cited research report.
10. Test fixtures, package build, and end-to-end verification.

Optional hosted models, remote feeds, ZAP, public npm publication, public marketplace submission, cloud dashboards, billing, and authenticated DAST remain outside v0.1.0.

## Verification plan

Completion is reported per gate rather than as a blanket success.

### Static and unit gates

- `PASS`: scanner, redaction, fingerprint, policy, receipt, authorization, URL, address-classification, intelligence-cache, and installer unit tests.
- `PASS`: strict TypeScript checking.
- `PASS`: no runtime dependencies beyond supported Node built-ins.
- `PASS`: scanner self-scan has no unexplained blocking finding.

### Fixture gates

- A vulnerable AI-scaffold fixture must produce expected blockers for client-exposed privilege, permissive data policy, missing authorization, unsafe model/tool flow, secret exposure, unsafe CI, and IaC exposure.
- A clean fixture must not produce a blocker.
- Every new blocking rule has at least one positive and one negative fixture.

### Live-probe gates

- Approved local test server produces a complete receipt.
- Missing TLS or configured production transport requirement produces the expected decision.
- Cross-origin redirect is recorded but not followed.
- Expired authorization makes zero requests.
- Unapproved target makes zero requests.
- Private/reserved destination is refused outside local mode.
- Response-body and request budgets are enforced.
- Cookie values and response bodies do not appear in output.

### Integration gates

- Codex plugin validates against the bundled plugin validator.
- Skill validates against the bundled skill validator.
- Hook fixtures prove recognized deploy commands call the gate and blocked outcomes deny execution.
- Installer succeeds in an isolated temporary repository for each adapter.
- Second installer run is idempotent.
- Existing conflicting files are preserved and reported.
- GitHub workflow and composite Action parse successfully and use least permissions.
- MCP initialize, tool-list, scan, and receipt flows pass over stdio.

### Packaging gates

- `npm pack` produces a tarball containing only intended files.
- A fresh temporary repository can invoke `npx <tarball> init --all` and run `guardian-unit doctor`.
- Package contents contain license and third-party notices.
- No secret, absolute development path, temporary directory, or credential is present in the tarball.

### Evidence boundaries

- Live third-party platform execution remains `UNPROVEN` unless the target host is available and the adapter is exercised there.
- Public npm, GitHub, and marketplace installation remain `UNPROVEN` until publication occurs through an authenticated owner account.
- Runtime cloud authorization, identity-provider policy, real secret rotation, and authenticated tenant isolation remain `UNPROVEN` in v0.1.0.

## Release and future phases

### Version 0.1.0: working local release gate

Deliver the engine, safe probe, evidence receipt, adapters, installer, tarball, and verification report.

### Version 0.2: initial intelligence plugin

Add signed offline OSV, CISA KEV, EPSS, and GitHub Advisory Database packs; exact source attribution; updater freshness policy; and canary enrichment. Resolve source-specific licensing and redistribution obligations before bundling data.

### Version 0.3: staging DAST and supplier assertions

Add opt-in ZAP Baseline with pinned image digest and strict context, fixed authenticated test plans, CSAF/VEX ingestion, and manual authorization-matrix workflows.

### Version 0.4: enterprise intelligence and policy

Add read-only STIX/TAXII connectors, enterprise mirrors, signed authorization, policy administration, transparency monitoring, and managed adapter deployment.

### Version 1.0: commercial control plane option

Only after validated demand, consider a hosted evidence index that receives opt-in redacted receipts rather than source code. Tenancy, authentication, retention, privacy, billing, and incident response become separate design projects.

## Success criteria

Version 0.1.0 succeeds when:

1. A user can install project-local integrations from a tarball with one command.
2. A deliberately vulnerable AI-generated application is blocked with reproducible, redacted, plain-language evidence.
3. A clean fixture passes without a blocking false positive.
4. An authorized target is probed within its exact request and scope budget.
5. An expired, redirected, private, or unauthorized target cannot receive unintended requests.
6. The same finding IDs and release outcome appear through CLI, MCP, and GitHub Action paths.
7. Agent hooks deny recognized deployment attempts when the authoritative CLI returns `BLOCK`, `HOLD`, or `REFUSED`.
8. Disabling a local agent adapter does not bypass the GitHub required check.
9. A local intelligence pack can be installed, validated, hashed, read, expired, rejected, and rolled back without executing data as code.
10. Every untested live integration or external publication is reported as `UNPROVEN` rather than implied complete.

## Sources

1. Lovable, [Security overview](https://docs.lovable.dev/features/security) and [Security view](https://docs.lovable.dev/features/security-view).
2. Semgrep, [Important updates to Semgrep OSS](https://semgrep.dev/blog/2024/important-updates-to-semgrep-oss/) and [Semgrep Rules License](https://semgrep.dev/legal/rules-license/).
3. OWASP ZAP, [ZAP Baseline Scan](https://www.zaproxy.org/docs/docker/baseline-scan/).
4. OWASP, [HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
5. OWASP, [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
6. IETF, [RFC 9116: A File Format to Aid in Security Vulnerability Disclosure](https://www.rfc-editor.org/rfc/rfc9116.html).
7. IETF, [RFC 9309: Robots Exclusion Protocol](https://www.rfc-editor.org/rfc/rfc9309.html).
8. OWASP, [Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
9. GitHub, [SARIF support for code scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).
10. GitHub, [Control deployments with environments and protection rules](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/control-deployments).
11. GitHub, [Finding and customizing actions](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/find-and-customize-actions).
12. OpenAI, [Plugins](https://learn.chatgpt.com/docs/plugins).
13. OpenAI, [Hooks](https://learn.chatgpt.com/docs/hooks).
14. Anthropic, [Claude Code hooks](https://code.claude.com/docs/en/hooks).
15. Microsoft, [Use hooks in VS Code](https://code.visualstudio.com/docs/agent-customization/hooks).
16. Microsoft, [Agent Plugins in VS Code](https://code.visualstudio.com/docs/agent-customization/agent-plugins).
17. GitHub, [Copilot coding-agent hooks](https://docs.github.com/en/copilot/concepts/agents/hooks).
18. GitHub, [Copilot agent plugins](https://docs.github.com/en/copilot/concepts/agents/about-plugins).
19. Google, [Antigravity hooks](https://www.antigravity.google/docs/hooks).
20. Google, [Antigravity plugins](https://www.antigravity.google/docs/plugins).
21. Cursor, [Rules](https://docs.cursor.com/context/rules-for-ai) and [Agent tools](https://docs.cursor.com/en/agent/tools).
22. Cognition, [Windsurf and Devin Desktop MCP](https://docs.devin.ai/desktop/cascade/mcp).
23. Lovable, [GitHub integration](https://docs.lovable.dev/integrations/github) and [Publish](https://docs.lovable.dev/features/publish).
24. CISA, [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
25. FIRST, [Exploit Prediction Scoring System data and API](https://www.first.org/epss/data).
26. OSV, [Data dumps and incremental changes](https://google.github.io/osv.dev/data/) and [API](https://google.github.io/osv.dev/api/).
27. OASIS, [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html).
28. OASIS, [TAXII 2.1](https://www.oasis-open.org/standard/taxii-version-2-1/).
29. The Update Framework, [Specification](https://theupdateframework.github.io/specification/).
30. Sigstore, [Verifying signatures](https://docs.sigstore.dev/cosign/verifying/verify/) and [Transparency logging](https://docs.sigstore.dev/logging/overview/).
31. SLSA, [Provenance](https://slsa.dev/spec/v1.2/provenance) and [Verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts).
32. in-toto, [Getting started](https://in-toto.io/docs/getting-started/).
33. NIST, [SP 800-115: Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final).
34. OWASP, [Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/00-Introduction_and_Objectives/).
35. Local reference, `/Users/admin/Documents/GitHub/agency-agents/security/security-penetration-tester.md`, accessed 2026-09-12. The engagement-scope, evidence, non-destructive testing, and remediation principles were used as domain reference; embedded executable examples were not treated as workflow instructions.
