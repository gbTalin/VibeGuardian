# Task 1 report — Guardian-Unit-Penetration-Testing Agent scanner core

## Status

DONE

## Implementation

- Ported the maintained local scanner core, static scanner set, reporting, optional agent review, server/MCP support, CLI, tests, and deliberately vulnerable fixture from the read-only Rampart source.
- Renamed the package to `guardian-unit-penetration-testing-agent`, the executable to `guardian-unit`, product display strings to Guardian-Unit-Penetration-Testing Agent, and runtime storage/configuration to `GUARDIAN_UNIT_HOME` and `~/.guardian-unit`.
- Replaced `.rampartignore` with `.guardianignore`; the walker reads `.guardianignore` plus `.gitignore` and continues to emit repository-relative locations and redacted evidence.
- Preserved zero runtime dependencies, Node `>=22.18.0`, Apache-2.0 licensing, scan history/redaction behavior, and deterministic-report contracts.
- Kept the inherited surface scanner source out of `buildEngine()` and removed CLI network/domain flags. The default engine roster is static-only; the fixture coverage confirms no network scanner ran.

## Commands and results

| Command | Result |
| --- | --- |
| `node --test 'test/core.test.ts'` | PASS — 14 tests, 4 suites, 0 failures (82.567 ms). |
| `node bin/guardian-unit.mjs scan examples/vulnerable-app --json` | PASS — valid JSON; 43 deterministic findings; 11 files scanned; static scanner roster only; evidence validation found no usable `AKIAIOSFODNN7EXAMPLE` or `hunter2`; all finding locations were relative. |
| `npm test` | PASS — 14 tests, 4 suites, 0 failures (75.826 ms). |
| `git diff --check` | PASS — no whitespace errors in tracked changes. |

## Files changed

- Root: `package.json`, `tsconfig.json`, `.gitignore`, `.guardianignore`
- Launcher: `bin/guardian-unit.mjs`
- Core product source: `src/version.ts`, `src/core/*`, `src/scanners/*`, `src/data/packages.ts`, `src/report/*`, `src/agents/*`, `src/server/*`, `src/cli.ts`
- Validation assets: `test/core.test.ts`, `examples/vulnerable-app/*`

## Self-review

- Product/package/launcher/Node-floor/runtime-dependency values match the task brief.
- No `RAMPART_*`, `.rampart`, or Rampart product references remain in the ported product files.
- `buildEngine()` registers seven static scanners and no surface scanner; CLI forces `allowNetwork: false` for scans.
- Fixture output shows explicit offline coverage limitations, relative paths, and redacted evidence.

## Concerns

- The inherited `src/scanners/surface.ts` remains in the source port for later replacement but is not imported or registered by the engine. Its direct use outside the public CLI/engine contract is not covered by this task’s test suite.
- TypeScript's dev dependency is declared but not installed in this clean worktree, so `npm run typecheck` was not an available local suite. Node 26 executed the TypeScript core/CLI and fixture successfully using native type stripping.

## Fix round 1/5 — security review remediation

### Changes

- Deleted `src/scanners/surface.ts` rather than leaving an exported/directly callable legacy live scanner. The engine remains seven static scanners only.
- Removed dashboard network/domain controls and server request handling for `network`/`domains`; server scans now force `allowNetwork: false`. The CLI no longer advertises `--skip surface`.
- Added provider HTTP failures that expose only bounded provider/status metadata, never response bodies.
- Added recursive output-boundary redaction for JSON, terminal, Markdown, SARIF, server JSON/SSE, persistence, legacy loaded findings, and triage notes. Triage notes are redacted on ingestion and before application/export.
- Corrected the canonical display name to `Guardian-Unit-Penetration-Testing Agent` across product, UI, CLI, MCP, reports, SARIF, fixture, and tests.
- Added integration regression tests for engine roster, absence of the legacy module, renamed home/ignore paths, offline CLI fixture output, help text, provider-body suppression, triage persistence, and JSON/Markdown/SARIF output redaction.

### Commands and exact results

| Command | Result |
| --- | --- |
| `node --test 'test/core.test.ts'` | PASS — 19 tests, 5 suites, 0 failures (304.339 ms). |
| `npm test` | PASS — 19 tests, 5 suites, 0 failures (301.852 ms). |
| `node bin/guardian-unit.mjs scan examples/vulnerable-app --json` plus contract assertion | PASS — 43 findings; scanners `ai-agents,ai-code,ci,code,dependencies,iac,secrets`; no surface scanner, no network coverage breach, no raw fixture secrets, and all locations relative. |
| `git diff --check` | PASS — no whitespace errors. |

### Updated self-review and concerns

- The prior retained-surface concern is resolved: no legacy surface-probe source remains.
- Static scan entry points are offline regardless of client/UI request fields; provider review remains an explicit separate feature and may use the configured provider.
- `npm run typecheck` remains unavailable in this clean worktree because TypeScript is declared but not installed; the full Node-native TypeScript test/CLI paths pass.

## Fix round 2/5 — MCP and public-output hardening

### Changes

- Routed every MCP JSON-RPC response and error through `safeJson`, while preserving one compact JSON object per stdout line; MCP text rendering now redacts findings and coverage before interpolation and stderr errors are redacted.
- Extended terminal redaction and SQLite regression coverage, including raw database-file inspection after persistence.
- Added real subprocess integration coverage with an injected `fetch` hook: CLI JSON, MCP `security_scan`, and dashboard JSON/SSE scans remain offline even when request metadata asks for network/domain behavior.
- Added real dashboard API coverage for redacted JSON errors and redacted SSE scan output, using a temporary loopback server and request token.

### Commands and exact results

| Command | Result |
| --- | --- |
| `node --test test/core.test.ts` | PASS — 20 tests, 5 suites, 0 failures (652.730 ms). |
| `npm test` | PASS — 20 tests, 5 suites, 0 failures (636.074 ms). |
| `git diff --check` | PASS — no whitespace errors. |

### Self-review

- MCP framing remains JSON Lines: output is still one JSON-RPC document per line after redaction.
- The no-outbound test uses real subprocess behavior and records every child-process `fetch` call; its log was empty for CLI, MCP, and dashboard static scans.
- The internal `Engine` library can still accept an explicit `allowNetwork: true`; public CLI, dashboard, and MCP static scan paths continue to force it false.
