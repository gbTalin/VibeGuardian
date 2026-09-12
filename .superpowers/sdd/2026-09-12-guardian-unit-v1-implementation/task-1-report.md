# Task 1 report — Guardian Unit scanner core

## Status

DONE

## Implementation

- Ported the maintained local scanner core, static scanner set, reporting, optional agent review, server/MCP support, CLI, tests, and deliberately vulnerable fixture from the read-only Rampart source.
- Renamed the package to `guardian-unit-penetration-testing-agent`, the executable to `guardian-unit`, product display strings to Guardian Unit, and runtime storage/configuration to `GUARDIAN_UNIT_HOME` and `~/.guardian-unit`.
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
