/**
 * Guardian-Unit-Penetration-Testing Agent canonical data model.
 *
 * Two rules govern everything in this file:
 *
 *  1. Provenance is never blurred. A finding produced by a deterministic
 *     matcher and a finding produced by a language model are different kinds of
 *     claim, and the model records which one it is. A product that presents an
 *     LLM's guess with the same authority as a regex match is lying to a
 *     security buyer.
 *
 *  2. Secret material never enters a Finding. Scanners report the *location*
 *     and *type* of a credential and a redacted preview. The value itself never
 *     travels into storage, a report, an agent prompt, or the UI.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** How much we trust that this finding is real and exploitable. */
export type Confidence = "confirmed" | "high" | "medium" | "low";

/**
 * Where the claim came from. Surfaced in the UI on every finding.
 * - `deterministic` — a pattern, parser, or dataflow rule matched. Reproducible.
 * - `llm-assisted`  — a security agent reasoned about code. Not reproducible; needs review.
 * - `hybrid`        — a deterministic match that an agent triaged, enriched, or confirmed.
 */
export type Provenance = "deterministic" | "llm-assisted" | "hybrid";

export type FindingStatus =
  | "open"
  | "triaged"
  | "fixed"
  | "suppressed"
  | "false-positive";

/** What kind of thing was scanned. */
export type TargetKind =
  | "repository"
  | "directory"
  | "cloud-account"
  | "web-surface"
  | "ci-pipeline"
  | "agent-config";

export interface Target {
  kind: TargetKind;
  /** Absolute path, URL, or account identifier. */
  id: string;
  /** Human label shown in the UI. */
  label: string;
}

export interface CodeLocation {
  /** Path relative to the scan root. Never absolute — absolute paths leak usernames into reports. */
  file: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
  /** Redacted excerpt. Guaranteed free of secret material. */
  snippet?: string;
}

export interface Remediation {
  /** One sentence a developer can act on. */
  summary: string;
  /** Ordered, concrete steps. */
  steps: string[];
  /** Optional replacement code, in the file's own language. */
  codeFix?: { language: string; before?: string; after: string };
  /**
   * Set when fixing the code is NOT sufficient — e.g. a leaked credential is
   * burned the moment it is committed and must be rotated at the provider.
   */
  outOfBandAction?: string;
}

export interface Mappings {
  /** e.g. ["CWE-798"] */
  cwe?: string[];
  /** OWASP Top 10 (web), e.g. ["A07:2021"] */
  owasp?: string[];
  /** OWASP Top 10 for LLM Applications, e.g. ["LLM01"] */
  owaspLlm?: string[];
  /** Compliance controls this evidences, e.g. ["SOC2:CC6.1", "PCI-DSS-4.0:6.2.4"] */
  compliance?: string[];
  /** CVE / GHSA / OSV identifiers for dependency findings. */
  advisories?: string[];
}

export interface Finding {
  /** Stable fingerprint. Survives line moves and reformatting. See fingerprint(). */
  id: string;
  ruleId: string;
  title: string;
  /** Plain-language explanation of what is wrong. No jargon without a gloss. */
  description: string;
  severity: Severity;
  confidence: Confidence;
  provenance: Provenance;
  /** Which scanner or agent produced this. */
  source: string;
  target: Target;
  location?: CodeLocation;
  /** The observable fact that triggered the rule. Redacted. */
  evidence: string;
  /** What an attacker does with this, concretely. The "so what". */
  exploit: string;
  remediation: Remediation;
  mappings: Mappings;
  tags: string[];
  status: FindingStatus;
  firstSeenAt: string;
  lastSeenAt: string;
  /** Free-text note from a human triager. */
  note?: string;
  /** Populated when an agent reviewed a deterministic finding. */
  agentReview?: {
    agent: string;
    model: string;
    verdict: "confirmed" | "likely" | "uncertain" | "false-positive";
    reasoning: string;
    reviewedAt: string;
  };
}

/** A finding as a scanner emits it — the engine fills in the rest. */
export type RawFinding = Omit<
  Finding,
  "id" | "target" | "status" | "firstSeenAt" | "lastSeenAt" | "provenance" | "source"
> & { provenance?: Provenance };

export interface RuleDoc {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** Which threat this addresses, for the rule catalogue in the UI. */
  threat: string;
  mappings: Mappings;
}

// ---------------------------------------------------------------------------
// Scanner plugin interface
// ---------------------------------------------------------------------------

export interface ScanContext {
  /** Absolute root of the scan. */
  root: string;
  target: Target;
  /** Files the walker found, relative to root, already filtered by ignore rules. */
  files: string[];
  /** Read a file's text. Cached; returns null for binary or unreadable files. */
  read(relPath: string): Promise<string | null>;
  /** True if the user allowed outbound network calls for this scan. Default false. */
  networkAllowed: boolean;
  /** Emit progress for the UI. */
  progress(message: string, fraction?: number): void;
  /** Cooperative cancellation. */
  signal: AbortSignal;
}

export interface Scanner {
  /** Stable machine name, e.g. "secrets". */
  name: string;
  /** Shown in the UI. */
  title: string;
  /** One sentence a non-specialist understands. */
  description: string;
  /** Rules this scanner can fire, for the catalogue and for coverage reporting. */
  rules: RuleDoc[];
  /** True if this scanner makes outbound network requests. */
  requiresNetwork?: boolean;
  /** Cheap pre-check: should this scanner run against this target at all? */
  appliesTo(ctx: ScanContext): boolean | Promise<boolean>;
  scan(ctx: ScanContext): Promise<RawFinding[]>;
}

// ---------------------------------------------------------------------------
// Scan results
// ---------------------------------------------------------------------------

export interface CoverageReport {
  /** What we actually looked at — the honest denominator. */
  filesScanned: number;
  filesSkipped: number;
  skipReasons: Record<string, number>;
  scannersRun: string[];
  scannersSkipped: { name: string; reason: string }[];
  /** Set when no model was configured, so no agent analysis ran. */
  agentAnalysisRan: boolean;
  /** Honest statement of what this scan did NOT check. Shown in every report. */
  limitations: string[];
}

export interface ScanResult {
  scanId: string;
  target: Target;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  findings: Finding[];
  coverage: CoverageReport;
  /** Non-fatal problems: a scanner crashed, a file was unreadable, a rate limit. */
  warnings: string[];
  guardianUnitVersion: string;
}
