import { buildEngine } from "../scanners/index.ts";
import { loadConfig, type GuardianUnitConfig } from "../core/config.ts";
import { rank } from "../core/finding.ts";
import { runAuthorizedProbe } from "../probe/probe.ts";
import { VERSION } from "../version.ts";
import { compareCodeUnits, decideRelease, exitCodeFor } from "./policy.ts";
import { buildReceipt, canonicalJson, sha256 } from "./receipt.ts";
import type { GateOptions, GateRun, ProbeResult } from "./types.ts";

function ruleDigest(): { version: string; digest: string } {
  const engine = buildEngine();
  const rules = engine
    .list()
    .flatMap((scanner) => scanner.rules.map((rule) => ({ scanner: scanner.name, ...rule })))
    .sort((a, b) => compareCodeUnits(`${a.scanner}:${a.id}`, `${b.scanner}:${b.id}`));
  return { version: VERSION, digest: sha256(canonicalJson(rules)) };
}

function requiredScanFailures(scan: GateRun["scan"]): string[] {
  return scan.coverage.scannersSkipped
    .filter((scanner) => scanner.reason.startsWith("error:"))
    .map((scanner) => `scanner ${scanner.name} failed`)
    .sort(compareCodeUnits);
}

/**
 * Run the local static half of the release gate. Probe and intelligence facts
 * are inputs so later modules add evidence without gaining policy authority.
 */
export async function runGate(options: GateOptions): Promise<GateRun> {
  const generatedAt = (options.now ?? (() => new Date()))();
  let probe = options.probe;
  if (!probe && (options.target !== undefined || options.authorizationPath !== undefined)) {
    if (!options.target || !options.authorizationPath) {
      probe = {
        state: "REFUSED",
        target: options.target ?? "UNPROVEN",
        requestCount: 0,
        requestBudget: 0,
        observations: [],
        findings: [],
        requiredFailures: ["--target and --authorization must be supplied together"],
        limitations: ["No network request was issued because approval inputs were incomplete."],
      } satisfies ProbeResult;
    } else {
      probe = await runAuthorizedProbe({ origin: options.target, authorizationPath: options.authorizationPath, now: generatedAt });
    }
  }
  const storedConfig = await loadConfig();
  const config: GuardianUnitConfig = { ...storedConfig, allowNetwork: false };
  const engine = buildEngine();
  const scan = await engine.scan(options.root, { config });
  if (probe) {
    scan.findings = rank([...scan.findings, ...(probe.findings ?? [])]);
    if (!scan.coverage.scannersRun.includes("authorized-probe") && probe.state !== "REFUSED") {
      scan.coverage.scannersRun.push("authorized-probe");
    }
    scan.coverage.limitations.push(...(probe.limitations ?? []));
  }
  const requiredFailures = requiredScanFailures(scan);
  const termination = probe?.state === "REFUSED" ? "REFUSED" as const : undefined;

  if (probe) {
    requiredFailures.push(...(probe.requiredFailures ?? []));
    if (probe.state === "PARTIAL") requiredFailures.push("authorized probe did not complete");
    if (probe.state === "REFUSED") requiredFailures.push("authorized probe was refused");
  } else if (options.approval?.target) {
    requiredFailures.push("authorized probe is unavailable");
  }

  const decision = decideRelease({
    findings: scan.findings,
    requiredFailures,
    policy: options.policy,
  });
  const receipt = buildReceipt({
    generatedAt: generatedAt.toISOString(),
    scan,
    decision,
    runtime: { version: VERSION, digest: sha256(`guardian-unit-runtime:${VERSION}`) },
    rules: ruleDigest(),
    intelligence: options.intelligence ?? { state: "UNPROVEN" },
    approval:
      options.approval ??
      (probe?.authorizationDigest ? { ...(probe.target ? { target: probe.target } : {}), digest: probe.authorizationDigest } : undefined),
    commit: options.commit,
    termination,
  });
  return { scan, probe, decision, receipt, termination, exitCode: exitCodeFor(termination ?? decision.outcome) };
}
