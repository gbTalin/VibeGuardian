import type { GateDecision, GateExitCode, GateFinding, GateInput, GateTermination, ReleaseOutcome, ReleasePolicy } from "./types.ts";

export const DEFAULT_RELEASE_POLICY: ReleasePolicy = {
  version: "guardian-unit-release-policy-v1",
  blockAtOrAbove: "high",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

/** Locale-independent ordering for canonical policy and receipt facts. */
export function compareCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function isAtOrAbove(severity: GateFinding["severity"], threshold: GateFinding["severity"]): boolean {
  return SEVERITY_ORDER.indexOf(severity) <= SEVERITY_ORDER.indexOf(threshold);
}

/**
 * Make the release decision from already-normalized facts only. This function
 * intentionally has no filesystem, process, clock, or network dependency.
 */
export function decideRelease(input: GateInput): GateDecision {
  const policy: ReleasePolicy = { ...DEFAULT_RELEASE_POLICY, ...input.policy };
  const open = input.findings.filter((finding) => finding.status === "open");
  const blockingFindings = open
    .filter(
      (finding) =>
        (finding.confidence === "confirmed" || finding.confidence === "high") &&
        isAtOrAbove(finding.severity, policy.blockAtOrAbove),
    )
    .map((finding) => finding.id)
    .sort(compareCodeUnits);
  const warningFindings = open
    .filter((finding) => !blockingFindings.includes(finding.id))
    .map((finding) => finding.id)
    .sort(compareCodeUnits);
  const requiredFailures = [...new Set(input.requiredFailures.map((failure) => failure.trim()).filter(Boolean))].sort(compareCodeUnits);

  const outcome: ReleaseOutcome =
    blockingFindings.length > 0 ? "BLOCK" : requiredFailures.length > 0 ? "HOLD" : warningFindings.length > 0 ? "WARN" : "PASS";
  const reasons = [
    ...blockingFindings.map((id) => `Blocking finding: ${id}`),
    ...requiredFailures.map((failure) => `Required evidence incomplete: ${failure}`),
    ...warningFindings.map((id) => `Non-blocking finding: ${id}`),
  ];

  return { outcome, policy, blockingFindings, warningFindings, requiredFailures, reasons };
}

/** Stable CLI contract; REFUSED and ERROR are terminal states, not outcomes. */
export function exitCodeFor(state: ReleaseOutcome | GateTermination): GateExitCode {
  switch (state) {
    case "PASS": return 0;
    case "BLOCK": return 1;
    case "WARN": return 2;
    case "HOLD": return 3;
    case "REFUSED": return 4;
    case "ERROR": return 5;
  }
}
