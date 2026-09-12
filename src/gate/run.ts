import { buildEngine } from "../scanners/index.ts";
import { loadConfig, type GuardianUnitConfig } from "../core/config.ts";
import { VERSION } from "../version.ts";
import { decideRelease, exitCodeFor } from "./policy.ts";
import { buildReceipt, canonicalJson, sha256 } from "./receipt.ts";
import type { GateOptions, GateRun } from "./types.ts";

function ruleDigest(): { version: string; digest: string } {
  const engine = buildEngine();
  const rules = engine
    .list()
    .flatMap((scanner) => scanner.rules.map((rule) => ({ scanner: scanner.name, ...rule })))
    .sort((a, b) => `${a.scanner}:${a.id}`.localeCompare(`${b.scanner}:${b.id}`));
  return { version: VERSION, digest: sha256(canonicalJson(rules)) };
}

function requiredScanFailures(scan: GateRun["scan"]): string[] {
  return scan.coverage.scannersSkipped
    .filter((scanner) => scanner.reason.startsWith("error:"))
    .map((scanner) => `scanner ${scanner.name} failed`)
    .sort();
}

/**
 * Run the local static half of the release gate. Probe and intelligence facts
 * are inputs so later modules add evidence without gaining policy authority.
 */
export async function runGate(options: GateOptions): Promise<GateRun> {
  const storedConfig = await loadConfig();
  const config: GuardianUnitConfig = { ...storedConfig, allowNetwork: false };
  const engine = buildEngine();
  const scan = await engine.scan(options.root, { config });
  const requiredFailures = requiredScanFailures(scan);

  if (options.probe) {
    requiredFailures.push(...(options.probe.requiredFailures ?? []));
    if (options.probe.state === "HOLD") requiredFailures.push("authorized probe did not complete");
    if (options.probe.state === "REFUSED") requiredFailures.push("authorized probe was refused");
  } else if (options.approval?.target) {
    // Task 3 owns probing. Do not silently accept a requested target before it
    // supplies strict authorization and SSRF checks.
    requiredFailures.push("authorized probe is unavailable");
  }

  const decision = decideRelease({
    findings: scan.findings,
    requiredFailures,
    policy: options.policy,
  });
  const receipt = buildReceipt({
    generatedAt: (options.now ?? (() => new Date()))().toISOString(),
    scan,
    decision,
    runtime: { version: VERSION, digest: sha256(`guardian-unit-runtime:${VERSION}`) },
    rules: ruleDigest(),
    intelligence: options.intelligence ?? { state: "UNPROVEN" },
    approval: options.approval,
    commit: options.commit,
  });
  return { scan, decision, receipt, exitCode: exitCodeFor(decision.outcome) };
}
