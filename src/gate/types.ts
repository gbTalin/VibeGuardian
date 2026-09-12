import type { Confidence, CoverageReport, FindingStatus, ScanResult, Severity } from "../core/types.ts";

/** A deployment decision. UNPROVEN is evidence state, never an outcome. */
export type ReleaseOutcome = "PASS" | "WARN" | "HOLD" | "BLOCK";
export type GateTermination = "REFUSED" | "ERROR";
export type GateExitCode = 0 | 1 | 2 | 3 | 4 | 5;

/** The policy needs only the normalized, non-sensitive parts of a finding. */
export interface GateFinding {
  id: string;
  severity: Severity;
  confidence: Confidence | "unproven";
  status: FindingStatus;
}

export interface ReleasePolicy {
  version: string;
  /** Open confirmed or high-confidence findings at this severity or worse block. */
  blockAtOrAbove: Severity;
}

export interface GateInput {
  findings: GateFinding[];
  /** Checks that did not produce enough trustworthy evidence for a release. */
  requiredFailures: string[];
  policy?: Partial<ReleasePolicy>;
}

export interface GateDecision {
  outcome: ReleaseOutcome;
  policy: ReleasePolicy;
  blockingFindings: string[];
  warningFindings: string[];
  requiredFailures: string[];
  reasons: string[];
}

/** Placeholder seam for Task 3's concrete authorized HTTP/TLS probe. */
export interface ProbeResult {
  state: "COMPLETE" | "HOLD" | "REFUSED";
  requiredFailures?: string[];
  findingIds?: string[];
  target?: string;
}

/** Placeholder seam for Task 4's signed local intelligence cache. */
export interface IntelligenceStatus {
  state: "CURRENT" | "STALE" | "UNPROVEN";
  digest?: string;
  sequence?: number;
  checkedAt?: string;
}

export interface EvidenceDigest {
  version: string;
  digest: string;
}

export interface CommitMetadata {
  sha: string;
  dirty: boolean;
}

/** A digest and optional exact origin from a validated approval record. */
export interface ApprovalMetadata {
  digest: string;
  target?: string;
}

export interface ReceiptFinding {
  fingerprint: string;
  severity: Severity;
  confidence: Confidence | "unproven";
  status: FindingStatus;
  disposition: "BLOCK" | "WARN" | "NONE";
  file?: string;
}

export interface ReceiptInput {
  generatedAt: string;
  scan: ScanResult;
  decision: GateDecision;
  runtime?: EvidenceDigest;
  rules?: EvidenceDigest;
  policy?: EvidenceDigest;
  intelligence?: IntelligenceStatus;
  approval?: ApprovalMetadata;
  commit?: CommitMetadata;
}

export interface ReleaseReceipt {
  schemaVersion: 1;
  generatedAt: string;
  runtime: EvidenceDigest;
  rules: EvidenceDigest;
  policy: EvidenceDigest;
  intelligence: IntelligenceStatus;
  approval?: ApprovalMetadata;
  commit: CommitMetadata;
  scan: {
    id: string;
    startedAt: string;
    finishedAt: string;
    coverage: CoverageReport;
    warnings: string[];
  };
  findings: ReceiptFinding[];
  outcome: ReleaseOutcome;
  exitCode: GateExitCode;
  digest: string;
}

export interface GateOptions {
  root: string;
  policy?: Partial<ReleasePolicy>;
  probe?: ProbeResult;
  intelligence?: IntelligenceStatus;
  approval?: ApprovalMetadata;
  commit?: CommitMetadata;
  /** Explicit clock seam so identical inputs yield an identical receipt. */
  now?: () => Date;
}

export interface GateRun {
  scan: ScanResult;
  decision: GateDecision;
  receipt: ReleaseReceipt;
  exitCode: GateExitCode;
}
