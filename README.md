# Guardian-Unit-Penetration-Testing Agent

Guardian-Unit is a hackathon-ready security release gate for nontechnical vibe coders. It checks source and configuration locally, optionally sends a few non-destructive requests to one explicitly authorized application origin, and returns a plain decision before deployment.

## See the core feature in one command

You need Node.js 22.18 or newer. The demo has zero runtime dependencies and does not need an API key.

```bash
npm run demo
```

That command starts a tiny app on a random loopback port, creates a ten-minute local authorization record, scans `examples/clean-app`, performs the bounded live probe, prints the release decision, then removes the temporary record and stops the app.

## Put it on your app in five minutes

From this Guardian-Unit checkout, replace the sample values with an origin you own or are explicitly authorized to assess:

```bash
node scripts/setup-demo.mjs /absolute/path/to/your-app \
  --target https://app.example.com \
  --environment production \
  --owner you@example.com
```

Setup is safe to repeat. It creates only missing files and reports `CONFLICT` instead of overwriting a different target record, Codex pointer, or GitHub workflow. The generated approval expires after 24 hours and allows at most four requests.

Run the gate directly:

```bash
node bin/guardian-unit.mjs gate /absolute/path/to/your-app \
  --target https://app.example.com \
  --authorization /absolute/path/to/your-app/.guardian-unit/targets.json \
  --json
```

Omit both `--target` and `--authorization` for a static-only source and configuration check. Supplying only one is refused.

## Read the decision

| Outcome | Meaning |
|---|---|
| `PASS` | The checks that ran found no release blocker. This is not proof the app is secure. |
| `WARN` | No confirmed blocker, but review the listed risks. |
| `HOLD` | Required evidence is incomplete, so deployment should wait. |
| `BLOCK` | A high-confidence blocking issue must be fixed before deployment. |
| `UNPROVEN` | A named control or integration was not observed or verified; it is never treated as success. |

The CLI preserves distinct exit codes: `0` pass, `1` block, `2` warn, `3` hold, `4` refused target/authorization, and `5` tool error.

## Codex deploy guard

The working local plugin is in `plugins/guardian-unit-penetration-testing-agent/`. Setup writes `.codex/guardian-unit.json` in your project with absolute pointers to that plugin, its launcher, and its local MCP server. Add the displayed plugin directory through Codex's local plugin loader.

The bundled `PreToolUse` hook recognizes a narrow set of agent-issued deploy commands and runs the same release gate. It stops on `HOLD`, `BLOCK`, malformed output, or tool failure. This hook is a convenience guard; a manual terminal or another deployment path can bypass it, so GitHub remains the authoritative gate.

## GitHub deployment gate

Setup installs `.github/workflows/guardian-unit-gate.yml` when that path is absent. Commit the workflow and the reviewed `.guardian-unit/targets.json` record.

- Pull requests run static source and configuration checks only.
- A maintainer can use **Run workflow** with an exact authorized target to start the live probe.
- The probe job uses the `guardian-unit-staging` or `guardian-unit-production` GitHub environment. Configure that environment as protected in repository settings before relying on it for deployment approval.
- Fork pull requests never receive a live target and never start the probe.
- The workflow uses only a checked-in or installed repository-local launcher, pins external Actions to full commit SHAs, and uploads the receipt, SARIF, Markdown, and raw JSON as evidence.

The required GitHub check must pass before your real deploy job. Guardian-Unit does not deploy the app itself.

## Safety boundary

Only probe an origin you own or have written authorization to assess. The live check is unauthenticated, rate-limited, and limited to the exact origin and approved request budget. It does not crawl, discover targets, submit forms, log in, guess credentials, inject payloads, exploit vulnerabilities, persist response bodies, or follow cross-origin redirects. Static source scanning stays local; the live probe necessarily sends requests to the approved origin.

This demo flow intentionally has no account authentication, product dashboard, extra pages, hosted control plane, or real-time threat-intelligence updater. It is not a replacement for a professional penetration test: business-logic flaws, authenticated authorization, cloud controls, tenant isolation, and many runtime risks remain unproven.

Potential adapters for VS Code/GitHub Copilot, Google Antigravity, Lovable, Cursor, and Windsurf are follow-ons and currently **UNPROVEN**. They are not implemented or enforced by this hackathon v1.

## Fix and rerun

Read each finding's file, impact, and remediation, make the smallest safe change, then rerun the same command. Never weaken the gate or broaden target authorization merely to turn a failure green.
