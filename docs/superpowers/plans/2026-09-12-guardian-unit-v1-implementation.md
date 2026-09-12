# Guardian-Unit v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a distributable local-first security release gate that scans source/configuration, safely probes an explicitly authorized URL, emits reproducible evidence, installs adapters for major coding agents, and preserves signed-data interfaces for future threat intelligence.

**Architecture:** Port the validated zero-runtime-dependency Rampart Node engine into Guardian-Unit, add isolated gate, probe, intelligence, and installer modules, then expose one CLI contract through MCP, agent plugins, hooks, and GitHub Actions. Deterministic findings and coverage feed a pure release-policy function; agent integrations never replace the authoritative CI decision.

**Tech Stack:** Node.js >=22.18, native TypeScript type stripping, built-in `node:test`, `node:sqlite`, `node:http`/`node:https`/`node:dns`, JSON/SARIF/Markdown, MCP stdio, project-local plugin templates, npm tarball packaging.

**Spec:** `docs/superpowers/specs/2026-09-12-guardian-unit-penetration-testing-agent-design.md`

## Global Constraints

- Display name is exactly `Guardian-Unit-Penetration-Testing Agent`; plugin/package ID is `guardian-unit-penetration-testing-agent`; CLI is `guardian-unit`.
- Node.js minimum is `22.18.0`; production runtime dependencies remain empty.
- Static scanning is local and network-off by default; no telemetry exists.
- Every live probe requires a valid `.guardian-unit/targets.json` authorization record before the first request.
- Production probe default is at most five unauthenticated, non-destructive requests with no crawler, payload injection, login, port scan, or subdomain discovery.
- Findings and receipts never contain complete secrets, cookie values, authorization headers, or response bodies.
- Deploy outcomes are `PASS`, `WARN`, `HOLD`, or `BLOCK`; `UNPROVEN` is an evidence state, not a success result.
- Intelligence packs are data-only. They cannot contain executable rules, prompts, commands, MCP configuration, authorization, or policy thresholds.
- CLI, plugins, and GitHub Action use immutable versions; no gate executes an unpinned `latest` package.
- Agent/IDE hooks are convenience preflight controls; GitHub required checks and protected environments are the authoritative deployment boundary.
- Public publication and live third-party-host verification remain `UNPROVEN` without authenticated destinations.

## File map

| Path | Responsibility |
|---|---|
| `package.json`, `bin/guardian-unit.mjs`, `src/version.ts` | Package identity, launcher, runtime floor, product metadata |
| `src/core/*`, `src/scanners/*`, `src/report/*`, `src/agents/*`, `src/server/*` | Ported and renamed Rampart engine, reports, optional review, UI, MCP |
| `src/gate/types.ts` | Outcome, policy, receipt, and command contracts |
| `src/gate/policy.ts` | Pure finding/coverage-to-outcome decision |
| `src/gate/receipt.ts` | Canonical receipt construction and SHA-256 digest |
| `src/gate/run.ts` | Gate orchestration and stable exit-code mapping |
| `src/probe/authorization.ts` | Authorization schema parsing and preflight validation |
| `src/probe/address.ts` | IP classification, DNS resolution, and safe target selection |
| `src/probe/client.ts` | Budgeted pinned HTTP/TLS requests and redirect control |
| `src/probe/probe.ts` | Five-request plan and normalized observations/findings |
| `src/intelligence/types.ts` | Provider, record, pack, cache, candidate, and freshness contracts |
| `src/intelligence/pack.ts` | Data-only schema, digest, sequence, and expiry validation |
| `src/intelligence/cache.ts` | Atomic project-local pack installation and last-known-good reads |
| `src/intelligence/candidates.ts` | Local deduplicated non-blocking candidate registry |
| `src/install/detect.ts` | Repository platform-marker detection |
| `src/install/templates.ts` | Template inventory and safe token substitution |
| `src/install/install.ts` | Idempotent project-local install, conflict report, and dry-run uninstall |
| `plugins/guardian-unit-penetration-testing-agent/*` | Codex plugin manifest, Skill, hook, MCP configuration, UI metadata |
| `templates/*` | Claude, VS Code/Copilot, Antigravity, Cursor, Windsurf, Lovable, GitHub templates |
| `action.yml`, `.github/workflows/guardian-unit-gate.yml` | First-party local composite Action and example authoritative gate workflow |
| `examples/vulnerable-app/*`, `examples/clean-app/*` | Static scanner acceptance fixtures |
| `test/fixtures/probe-server.ts` | Controlled local live-probe server |
| `test/*.test.ts` | Unit, integration, installer, MCP, fixture, and package tests |
| `README.md`, `SECURITY.md`, `LICENSE`, `THIRD_PARTY_NOTICES.md` | Installation, security boundary, licensing, and operator guidance |
| `docs/research/guardian-unit-v1-research.md` | Cited platform, methodology, competition, and intelligence research |
| `docs/verification/v1-evidence.md` | Commands, outcomes, and explicit UNPROVEN gates |

---

### Task 1: Port and rename the validated scanner core

**Files:**
- Create: `package.json`, `bin/guardian-unit.mjs`, `src/version.ts`
- Create: `src/core/*`, `src/scanners/*`, `src/report/*`, `src/agents/*`, `src/server/*`
- Create: `test/core.test.ts`, `examples/vulnerable-app/*`, `.gitignore`, `.guardianignore`

**Interfaces:**
- Consumes: existing Rampart source at `/Users/admin/Documents/GitHub/agency-agents/.claude/worktrees/security-agent-platform-strategy-d0c8f1/rampart`
- Produces: `buildEngine()`, `ScanResult`, report functions, optional agent review, and `guardian-unit scan|rules|doctor|mcp`

- [ ] **Step 1: Copy only maintained source and fixtures**

Copy `bin`, `src`, `test/core.test.ts`, `examples/vulnerable-app`, `package.json`, `tsconfig.json`, `.gitignore`, and `.rampartignore`; exclude `node_modules`, databases, reports, and historical strategy output.

- [ ] **Step 2: Rename product and paths**

Set package identity and executable:

```json
{
  "name": "guardian-unit-penetration-testing-agent",
  "version": "0.1.0",
  "type": "module",
  "license": "Apache-2.0",
  "engines": { "node": ">=22.18.0" },
  "bin": { "guardian-unit": "./bin/guardian-unit.mjs" },
  "dependencies": {}
}
```

Change user configuration from `RAMPART_HOME`/`~/.rampart` to `GUARDIAN_UNIT_HOME`/`~/.guardian-unit`; change `.rampartignore` to `.guardianignore`; preserve scan-relative paths and secret redaction.

- [ ] **Step 3: Run inherited tests before feature work**

Run: `node --test 'test/core.test.ts'`

Expected: all inherited tests pass under Guardian-Unit naming; failures caused only by intentional renamed paths are corrected without weakening assertions.

- [ ] **Step 4: Verify scanner fixture**

Run: `node bin/guardian-unit.mjs scan examples/vulnerable-app --json`

Expected: valid JSON with nonzero deterministic findings, redacted evidence, repository-relative locations, and explicit coverage.

### Task 2: Add release policy and reproducible receipts

**Files:**
- Create: `src/gate/types.ts`, `src/gate/policy.ts`, `src/gate/receipt.ts`, `src/gate/run.ts`
- Modify: `src/cli.ts`, `src/report/markdown.ts`, `src/report/sarif.ts`
- Test: `test/gate.test.ts`, `test/receipt.test.ts`

**Interfaces:**
- Consumes: `ScanResult`, optional `ProbeResult`, optional `IntelligenceStatus`
- Produces: `decideRelease(input: GateInput): GateDecision`, `buildReceipt(input: ReceiptInput): ReleaseReceipt`, `runGate(options: GateOptions): Promise<GateRun>`, `exitCodeFor(outcome): 0|1|2|3|4|5`

- [ ] **Step 1: Write failing policy tests**

Test the exact matrix:

```ts
assert.equal(decideRelease({ findings: [open("critical", "confirmed")], requiredFailures: [] }).outcome, "BLOCK");
assert.equal(decideRelease({ findings: [open("medium", "confirmed")], requiredFailures: [] }).outcome, "WARN");
assert.equal(decideRelease({ findings: [], requiredFailures: ["probe timeout"] }).outcome, "HOLD");
assert.equal(decideRelease({ findings: [], requiredFailures: [] }).outcome, "PASS");
assert.equal(decideRelease({ findings: [open("high", "unproven")], requiredFailures: [] }).outcome, "WARN");
```

Run: `node --test test/gate.test.ts`

Expected: FAIL because `decideRelease` does not exist.

- [ ] **Step 2: Implement pure policy and stable exit mapping**

Implement no I/O in `policy.ts`. Confirmed/high-confidence open findings at configured severity block; unproven findings warn; required evidence failure holds; refused authorization maps to exit `4`; internal tool failure maps to exit `5`.

- [ ] **Step 3: Write failing canonical-receipt test**

Create equivalent inputs with object properties inserted in different orders and assert identical canonical JSON and digest. Assert redaction rejects keys matching `secret`, `token`, `authorization`, `cookie`, and `responseBody`.

Run: `node --test test/receipt.test.ts`

Expected: FAIL because receipt functions do not exist.

- [ ] **Step 4: Implement receipt construction**

Use recursive lexicographic key sorting, SHA-256 over canonical JSON without the `digest` property, ISO UTC timestamps, relative paths, finding fingerprints, runtime/rules/policy/intelligence hashes, authorization hash, commit metadata, coverage, outcome, and exit code.

- [ ] **Step 5: Add `gate` CLI command**

Support:

```text
guardian-unit gate [path]
  --target <exact-origin>
  --authorization <path>
  --policy <path>
  --receipt <path>
  --sarif <path>
  --markdown <path>
  --json
```

Write complete stdout before setting `process.exitCode`; never call `process.exit()`.

- [ ] **Step 6: Run policy and receipt tests**

Run: `node --test test/gate.test.ts test/receipt.test.ts`

Expected: PASS.

### Task 3: Implement the authorized HTTP/TLS probe

**Files:**
- Create: `src/probe/authorization.ts`, `src/probe/address.ts`, `src/probe/client.ts`, `src/probe/probe.ts`
- Modify: `src/scanners/index.ts`, `src/cli.ts`
- Test: `test/probe.test.ts`, `test/fixtures/probe-server.ts`

**Interfaces:**
- Consumes: `loadAuthorization(path, origin, now): AuthorizedTarget`
- Produces: `resolveApprovedTarget(target): Promise<ResolvedTarget>`, `requestPinned(input): Promise<ProbeResponse>`, `runAuthorizedProbe(input): Promise<ProbeResult>`

- [ ] **Step 1: Write authorization refusal tests**

Assert expired approval, origin mismatch, invalid scheme, user-info, fragment, unapproved port, malformed JSON, and production IP literal return `REFUSED` before the fixture server observes a request.

Run: `node --test test/probe.test.ts`

Expected: FAIL because authorization and probe modules do not exist.

- [ ] **Step 2: Implement strict authorization parsing**

Validate `schemaVersion: 1`, exact normalized origin, environment enum, owner, parseable UTC dates, future expiry, request budget `1..20`, redirects `0..5`, timeouts `100..60000`, rate `0.1..10`, boolean CORS flag, and relative approved paths beginning with one `/` and containing no scheme or traversal.

- [ ] **Step 3: Add address classification tests**

Test IPv4/IPv6 loopback, RFC1918, link-local, CGNAT, multicast, unspecified, documentation, and public examples. Permit loopback only for `environment: local` and exact local hostnames.

- [ ] **Step 4: Implement DNS and pinned-request safety**

Resolve A and AAAA, reject forbidden results, connect to one validated address through a custom `lookup`, preserve approved hostname for TLS SNI and Host, disable automatic redirects and proxy inheritance, and cap headers/body/time. Re-resolve and revalidate before each followed same-origin redirect.

- [ ] **Step 5: Implement the bounded request plan**

Issue only HTTPS root, HTTP root redirect observation, `/.well-known/security.txt`, `/robots.txt`, and optional `OPTIONS /`. Never follow cross-origin redirects. Never persist response bodies or cookie values. Emit normalized TLS/header/cookie/error observations and coverage.

- [ ] **Step 6: Prove budgets and redaction**

Assert request count never exceeds authorization, body reads stop at the byte cap, cross-origin redirects are not followed, timeout is `HOLD`, private target is `REFUSED`, and output contains no fixture cookie value or body secret.

Run: `node --test test/probe.test.ts`

Expected: PASS.

### Task 4: Implement future threat-intelligence contracts and local cache

**Files:**
- Create: `src/intelligence/types.ts`, `src/intelligence/pack.ts`, `src/intelligence/cache.ts`, `src/intelligence/candidates.ts`
- Test: `test/intelligence.test.ts`, `test/candidates.test.ts`

**Interfaces:**
- Produces: `validatePack(input, highestSequence, now): PackValidation`, `installPack(root, pack): Promise<IntelligenceStatus>`, `readCurrentPack(root, now): Promise<IntelligenceState>`, `recordCandidate(root, input): Promise<CandidateRecord>`
- Consumes later: `runGate` reads `IntelligenceState`; future updater implements `IntelligenceProvider`

- [ ] **Step 1: Write failing pack-validation tests**

Test valid project pack, digest mismatch, lower sequence, expiry, unsupported schema, executable-field rejection, oversized fields, and record-count mismatch.

Run: `node --test test/intelligence.test.ts`

Expected: FAIL because intelligence modules do not exist.

- [ ] **Step 2: Implement data-only types and validation**

Reject keys named or shaped as `command`, `script`, `prompt`, `tool`, `mcp`, `hook`, `authorization`, `policy`, `code`, or executable URL. Accept only normalized vulnerability, exploit-priority, applicability, and CTI record fields from the spec. Recompute SHA-256 and enforce monotonic sequence and expiry.

- [ ] **Step 3: Implement atomic cache installation**

Write to `.guardian-unit/intelligence/staging-<digest>`, validate, rename to immutable `packs/<sequence>-<digest>`, then atomically replace `current.json`. Preserve `previous.json`; a failed install leaves current unchanged.

- [ ] **Step 4: Write and implement candidate tests**

Assert equivalent evidence produces one stable candidate; candidate records contain redacted generalized features, positive/negative fixture descriptions, and `state: "local-canary"`; they contain no source snippet, secret, URL, customer name, executable rule, or blocking policy.

Run: `node --test test/intelligence.test.ts test/candidates.test.ts`

Expected: PASS.

### Task 5: Extend MCP and agent-facing behavior

**Files:**
- Modify: `src/server/mcp.ts`
- Create: `test/mcp.test.ts`
- Create: `security/guardian-unit-penetration-tester.md`

**Interfaces:**
- Produces MCP tools: `guardian_security_scan`, `guardian_release_gate`, `guardian_explain_finding`, `guardian_get_receipt`, `guardian_intelligence_status`
- Consumes: CLI-equivalent engine, gate, receipt, and intelligence functions; no subprocess recursion

- [ ] **Step 1: Write failing MCP protocol test**

Spawn `node bin/guardian-unit.mjs mcp`, send newline-delimited JSON-RPC initialize and `tools/list`, and assert all five tools have strict schemas and no deploy, exploit, write, or auto-fix capability.

- [ ] **Step 2: Implement tools through shared functions**

Use shared engine functions directly. Gate tool requires authorization for a target; MCP mode does not force network off when a valid gate authorization exists, but no general network flag is exposed. Every result includes coverage and evidence status.

- [ ] **Step 3: Add safe specialist definition**

Adapt the supplied penetration-tester reference to source and authorized-probe interpretation. Require explicit scope; prohibit exploitation, credential attacks, persistence, lateral movement, destructive requests, and target discovery. Require impact, evidence, remediation, retest, and `UNPROVEN` boundaries.

- [ ] **Step 4: Run MCP test**

Run: `node --test test/mcp.test.ts`

Expected: PASS with clean child-process shutdown.

### Task 6: Build Codex and cross-platform adapter templates

**Files:**
- Create: `plugins/guardian-unit-penetration-testing-agent/.codex-plugin/plugin.json`
- Create: `plugins/guardian-unit-penetration-testing-agent/skills/guardian-unit-penetration-testing-agent/SKILL.md`
- Create: `plugins/guardian-unit-penetration-testing-agent/skills/guardian-unit-penetration-testing-agent/agents/openai.yaml`
- Create: `plugins/guardian-unit-penetration-testing-agent/hooks/hooks.json`
- Create: `plugins/guardian-unit-penetration-testing-agent/scripts/pre-deploy-gate.mjs`
- Create: `plugins/guardian-unit-penetration-testing-agent/.mcp.json`
- Create: `templates/claude-code/*`, `templates/vscode-copilot/*`, `templates/antigravity/*`, `templates/cursor/*`, `templates/windsurf/*`, `templates/lovable/*`
- Test: `test/hooks.test.ts`, `test/adapters.test.ts`

**Interfaces:**
- Consumes: installed absolute or repository-relative `guardian-unit` launcher and `guardian-unit gate`
- Produces: platform-native files that delegate decisions to the same CLI

- [ ] **Step 1: Scaffold and validate the Codex plugin shape**

Manifest name is `guardian-unit-penetration-testing-agent`; package Skill auto-invokes for deployment/security review; hook matches only shell/deploy tool calls; MCP points to the local launcher. No manifest contains unsupported `hooks` fields when the companion hook file is used.

- [ ] **Step 2: Write hook contract tests**

Feed synthetic host hook events for recognized deploy commands, unrelated commands, `PASS`, `WARN`, `HOLD`, `BLOCK`, timeout, and malformed input. Assert unrelated commands allow without scanning; blocking outcomes deny; warnings allow with context; failure never silently allows a recognized deployment.

- [ ] **Step 3: Implement one shared hook adapter**

`pre-deploy-gate.mjs` parses stdin, extracts a command from documented host shapes, matches a conservative command list, runs the local gate with inherited working directory and bounded timeout, and emits host-specific allow/deny JSON selected by `GUARDIAN_UNIT_HOOK_HOST`.

- [ ] **Step 4: Add platform templates**

Create:

- Claude Code plugin hook, Skill, and MCP files.
- VS Code/GitHub Copilot Agent Plugin metadata and Preview `PreToolUse` hook.
- Antigravity plugin manifest, hook, Skill, rule, and MCP config.
- Cursor rules/command/MCP guided preflight without false enforcement claims.
- Windsurf Skill/workflow/MCP guided preflight without false enforcement claims.
- Lovable importable `SKILL.md` that requires the GitHub gate for external deployment and states native Publish is not intercepted.

- [ ] **Step 5: Validate adapters**

Parse every JSON/YAML-like template with deterministic structural tests; scan for `@latest`, placeholder tokens left after rendering, unsupported security claims, and deployment commands that do not call the gate.

Run: `node --test test/hooks.test.ts test/adapters.test.ts`

Expected: PASS.

### Task 7: Build the idempotent project installer

**Files:**
- Create: `src/install/detect.ts`, `src/install/templates.ts`, `src/install/install.ts`
- Modify: `src/cli.ts`
- Test: `test/install.test.ts`

**Interfaces:**
- Produces: `detectPlatforms(root): PlatformId[]`, `planInstall(options): InstallPlan`, `applyInstall(plan): Promise<InstallResult>`, `planUninstall(root): InstallPlan`
- CLI: `guardian-unit init`, `guardian-unit doctor`, `guardian-unit uninstall --dry-run`

- [ ] **Step 1: Write failing isolated-install tests**

Create temporary repositories with Codex, Claude, VS Code/Copilot, Antigravity, Cursor, Windsurf, Lovable, and GitHub markers. Assert `--all` selects applicable templates and explicit `--platform` restricts output.

- [ ] **Step 2: Implement platform detection and safe rendering**

Use filesystem markers only. Render exact runtime version, package root, target, environment, and owner. Reject newline/control characters in substitutions. Never resolve a mutable npm dist-tag.

- [ ] **Step 3: Implement conflict-safe application**

Create absent files, replace only files carrying a Guardian-Unit ownership marker and matching recorded digest, and report all other conflicts without overwriting. Store `.guardian-unit/install-manifest.json` with created paths and digests.

- [ ] **Step 4: Prove idempotence and dry-run uninstall**

Run install twice and assert the second result has zero writes. Change an installed file and assert reinstall preserves it as a conflict. Assert uninstall dry run lists only manifest-owned paths and performs no deletion.

Run: `node --test test/install.test.ts`

Expected: PASS.

### Task 8: Add authoritative GitHub Actions integration

**Files:**
- Create: `action.yml`
- Create: `.github/workflows/guardian-unit-gate.yml`
- Create: `templates/github/.github/workflows/guardian-unit-gate.yml`
- Test: `test/github-action.test.ts`

**Interfaces:**
- Consumes: repository-local Guardian-Unit package and `.guardian-unit/targets.json`
- Produces: SARIF, Markdown report, JSON receipt, job summary, and failing required check

- [ ] **Step 1: Write workflow structure test**

Assert checkout is pinned to a full SHA or is first-party local, permissions are `contents: read` and `security-events: write` only where SARIF upload requires it, no pull-request secrets are exposed, no `@latest` appears, and gate exit codes retain `HOLD` versus `BLOCK` in the summary.

- [ ] **Step 2: Implement composite Action**

Inputs: `path`, `target`, `authorization`, `fail-on-warn`; outputs: `outcome`, `receipt`, `sarif`. Invoke the repository-local launcher and always upload evidence through a final step while preserving the original gate exit.

- [ ] **Step 3: Implement workflow template**

Trigger pull requests and manual dispatch for static gating; run authorized URL probe only on protected deployment jobs with target configuration present. Do not probe fork PR targets.

- [ ] **Step 4: Run Action tests**

Run: `node --test test/github-action.test.ts`

Expected: PASS.

### Task 9: Write user, security, and research documentation

**Files:**
- Create: `README.md`, `SECURITY.md`, `LICENSE`, `THIRD_PARTY_NOTICES.md`
- Create: `docs/research/guardian-unit-v1-research.md`
- Create: `docs/verification/v1-evidence.md`

**Interfaces:**
- Consumes: verified CLI, exact installer syntax, adapter limitations, source research
- Produces: non-technical quick start, operator safety contract, cited research, and evidence ledger

- [ ] **Step 1: Write the quick start from tested commands**

Document tarball install, `init --all`, authorization record, `scan`, `gate`, reports, MCP, CI, outcome meanings, and how to fix/retest. State Node version and no-runtime-dependency boundary.

- [ ] **Step 2: Document security and authorization boundaries**

State prohibited activity, production/staging request behavior, target ownership requirement, privacy/data-egress posture, responsible disclosure, update-channel separation, and why the product is not a professional pentest replacement.

- [ ] **Step 3: Produce the cited research artifact**

Condense the approved design research into a self-contained report covering methodology, platform integration evidence, competitor overlap, threat sources, secure updates, product positioning, and explicit evidence gaps. Use official sources and the attached specialist reference as a labeled local source.

- [ ] **Step 4: Seed the verification ledger**

List every required command and status as `PENDING`; replace each with actual `PASS`, `HOLD`, or `UNPROVEN` plus evidence during Task 10. No gate may be marked pass from static review alone.

### Task 10: Package and execute the full verification matrix

**Files:**
- Modify: `package.json`, `.gitignore`, `.npmignore`, `docs/verification/v1-evidence.md`
- Create: `examples/clean-app/*`
- Test: all `test/*.test.ts`

**Interfaces:**
- Consumes: all prior tasks
- Produces: distributable npm tarball and evidence-backed release decision

- [ ] **Step 1: Run deterministic test suite**

Run: `node --test 'test/*.test.ts'`

Expected: all tests pass, zero skipped tests unless the evidence ledger labels the corresponding external integration `UNPROVEN`.

- [ ] **Step 2: Run strict type checking**

Run: `npm run typecheck`

Expected: zero diagnostics.

- [ ] **Step 3: Run vulnerable and clean fixture acceptance**

Run:

```bash
node bin/guardian-unit.mjs gate examples/vulnerable-app --json
node bin/guardian-unit.mjs gate examples/clean-app --json
```

Expected: vulnerable fixture returns `BLOCK`; clean fixture returns `PASS` or a documented non-blocking `WARN`, never a false `BLOCK`.

- [ ] **Step 4: Run authorized local probe acceptance**

Start the test fixture server on a dynamically assigned loopback port, create a time-bounded local authorization record, run the gate, and assert request count, receipt fields, redaction, and outcome. Repeat with expired authorization and assert the server saw zero new requests.

- [ ] **Step 5: Validate Codex plugin and Skill**

Run the bundled plugin validator and skill validator against `plugins/guardian-unit-penetration-testing-agent`; expected result is success without placeholders or unsupported manifest fields.

- [ ] **Step 6: Package and inspect**

Run: `npm pack --json`

Expected: one versioned `.tgz`; inspect its file list for intended source/templates/docs/license only, and scan it for absolute development paths, temporary paths, secrets, and `@latest`.

- [ ] **Step 7: Prove one-command clean installation**

In a new temporary repository, run `npx <absolute-tarball> init --all --target <local-origin> --environment local --owner test@example.invalid`, then run `node node_modules/.bin/guardian-unit doctor` or the installed package executable as resolved by npm. Expected: adapters installed, second init idempotent, doctor successful.

- [ ] **Step 8: Run Guardian-Unit against itself**

Run: `node bin/guardian-unit.mjs gate . --json`

Expected: no unexplained blocking findings. Rule definitions and fixtures may be explicitly ignored only through narrow documented path exclusions.

- [ ] **Step 9: Finalize evidence ledger**

Record command, timestamp, exit code, material output, and artifact path for each gate. Label live Codex/Claude/VS Code/Copilot/Antigravity/Cursor/Windsurf/Lovable host execution and public publication `UNPROVEN` unless actually exercised.

- [ ] **Step 10: Commit the verified release**

Commit only after all local gates either pass or have an explicit `HOLD` accepted by the owner. Suggested message: `feat: build Guardian-Unit penetration testing agent v1`.
