import { createHash } from "node:crypto";
import { redact } from "../core/redact.ts";
import type { CoverageReport } from "../core/types.ts";
import { compareCodeUnits, exitCodeFor } from "./policy.ts";
import type { EvidenceDigest, ReceiptFinding, ReceiptInput, ReleaseReceipt } from "./types.ts";

const UNSAFE_RECEIPT_KEY = /(secret|token|authorization|cookie|responsebody)/i;

const ABSOLUTE_FILESYSTEM_PATH = /^(?:\/|[A-Za-z]:[\\/]|\\\\|\/\/)/;
const FILESYSTEM_PATH_IN_TEXT = /(^|[\s=:\[({,;!?'"`])((?:[A-Za-z]:[\\/]|\\\\|(?<!:)\/\/|(?<!http:)(?<!https:)\/(?!\/))[^\s"'`<>\])},;]*)/gi;
const FILE_URI_IN_TEXT = /\bfile:\/\/\/?[^\s"'`<>]*/g;

/** Reject dangerous fields before a value reaches the canonical receipt boundary. */
export function assertSafeReceiptValue(value: unknown, path = "receipt"): void {
  // Undefined is omitted by JSON.stringify and by sortJson below.
  if (value === undefined) return;
  if (typeof value === "string") {
    if (redact(value) !== value) throw new Error(`Unsafe receipt value at ${path}.`);
    return;
  }
  if (value === null || typeof value === "boolean" || typeof value === "number") return;
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertSafeReceiptValue(entry, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") throw new Error(`Unsupported receipt value at ${path}.`);
  for (const [key, entry] of Object.entries(value)) {
    if (UNSAFE_RECEIPT_KEY.test(key)) throw new Error(`Unsafe receipt key at ${path}.${key}.`);
    assertSafeReceiptValue(entry, `${path}.${key}`);
  }
}

function serializeCanonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Receipt values must be finite JSON numbers.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(serializeCanonicalJson).join(",")}]`;
  if (!value || typeof value !== "object") throw new Error("Receipt values must be JSON-compatible.");
  return `{${Object.entries(value as Record<string, unknown>)
    .filter(([, entry]) => entry !== undefined)
    .sort(([a], [b]) => compareCodeUnits(a, b))
    .map(([key, entry]) => `${JSON.stringify(key)}:${serializeCanonicalJson(entry)}`)
    .join(",")}}`;
}

/** Canonical JSON: recursively sorted object keys with no whitespace. */
export function canonicalJson(value: unknown): string {
  assertSafeReceiptValue(value);
  return serializeCanonicalJson(value);
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function digestFor(value: unknown): string {
  return sha256(canonicalJson(value));
}

function normalizeIsoUtc(value: string, name: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || !value.endsWith("Z")) throw new Error(`${name} must be an ISO UTC timestamp.`);
  return date.toISOString();
}

function pathTail(value: string): string {
  const parts = value.replace(/^[A-Za-z]:[\\/]?/, "").split(/[\\/]+/).filter(Boolean);
  return parts.slice(-2).join("/") || "path";
}

function sanitizeText(value: string): string {
  return redact(value)
    .replace(FILE_URI_IN_TEXT, (uri) => `[path:${pathTail(uri.replace(/^file:\/\//, ""))}]`)
    .replace(FILESYSTEM_PATH_IN_TEXT, (_match, prefix: string, path: string) => `${prefix}[path:${pathTail(path)}]`);
}

function relativePath(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const sanitized = sanitizeText(value);
  if (ABSOLUTE_FILESYSTEM_PATH.test(value)) return pathTail(value);
  const parts = sanitized.replaceAll("\\", "/").split("/");
  if (parts.some((part) => part === "..")) {
    throw new Error("Receipt finding paths must be relative to the scan root.");
  }
  return parts.filter((part) => part && part !== ".").join("/");
}

function projectCoverage(coverage: CoverageReport): CoverageReport {
  const skipReasons: Record<string, number> = {};
  for (const [reason, count] of Object.entries(coverage.skipReasons).sort(([a], [b]) => compareCodeUnits(a, b))) {
    const projectedReason = sanitizeText(reason);
    skipReasons[projectedReason] = (skipReasons[projectedReason] ?? 0) + count;
  }
  return {
    filesScanned: coverage.filesScanned,
    filesSkipped: coverage.filesSkipped,
    skipReasons,
    scannersRun: coverage.scannersRun.map(sanitizeText).sort(compareCodeUnits),
    scannersSkipped: coverage.scannersSkipped
      .map((scanner) => ({ name: sanitizeText(scanner.name), reason: sanitizeText(scanner.reason) }))
      .sort((a, b) => compareCodeUnits(`${a.name}\u0000${a.reason}`, `${b.name}\u0000${b.reason}`)),
    agentAnalysisRan: coverage.agentAnalysisRan,
    limitations: coverage.limitations.map(sanitizeText).sort(compareCodeUnits),
  };
}

function projectDigest(input: EvidenceDigest): EvidenceDigest {
  return { version: sanitizeText(input.version), digest: sanitizeText(input.digest) };
}

function receiptFindings(input: ReceiptInput): ReceiptFinding[] {
  const blocking = new Set(input.decision.blockingFindings);
  const warnings = new Set(input.decision.warningFindings);
  return input.scan.findings
    .map((finding) => ({
      fingerprint: sanitizeText(finding.id),
      severity: finding.severity,
      confidence: finding.confidence,
      status: finding.status,
      disposition: blocking.has(finding.id) ? "BLOCK" : warnings.has(finding.id) ? "WARN" : "NONE",
      ...(finding.location?.file ? { file: relativePath(finding.location.file) } : {}),
    }))
    .sort((a, b) => compareCodeUnits(a.fingerprint, b.fingerprint));
}

function defaultDigest(version: string, label: string): EvidenceDigest {
  return { version, digest: sha256(`${label}:${version}`) };
}

/**
 * Build a minimal, redacted receipt. It deliberately derives its finding
 * summary rather than copying finding evidence, snippets, URLs, or headers.
 */
export function buildReceipt(input: ReceiptInput): ReleaseReceipt {
  const runtime = projectDigest(input.runtime ?? defaultDigest(input.scan.guardianUnitVersion, "runtime"));
  const rules = projectDigest(input.rules ?? defaultDigest(input.scan.guardianUnitVersion, "rules"));
  const policy = projectDigest(input.policy ?? { version: input.decision.policy.version, digest: digestFor(input.decision.policy) });
  const intelligence = input.intelligence ?? { state: "UNPROVEN" as const };
  const commit = input.commit ?? { sha: "UNPROVEN", dirty: true };
  const base = {
    schemaVersion: 1 as const,
    generatedAt: normalizeIsoUtc(input.generatedAt, "generatedAt"),
    runtime,
    rules,
    policy,
    intelligence: {
      state: sanitizeText(intelligence.state) as typeof intelligence.state,
      ...(intelligence.digest ? { digest: sanitizeText(intelligence.digest) } : {}),
      ...(intelligence.sequence !== undefined ? { sequence: intelligence.sequence } : {}),
      ...(intelligence.checkedAt ? { checkedAt: normalizeIsoUtc(intelligence.checkedAt, "intelligence.checkedAt") } : {}),
    },
    ...(input.approval
      ? { approval: { digest: sanitizeText(input.approval.digest), ...(input.approval.target ? { target: sanitizeText(input.approval.target) } : {}) } }
      : {}),
    commit: { sha: sanitizeText(commit.sha), dirty: commit.dirty },
    scan: {
      id: sanitizeText(input.scan.scanId),
      startedAt: normalizeIsoUtc(input.scan.startedAt, "scan.startedAt"),
      finishedAt: normalizeIsoUtc(input.scan.finishedAt, "scan.finishedAt"),
      coverage: projectCoverage(input.scan.coverage),
      warnings: input.scan.warnings.map(sanitizeText).sort(compareCodeUnits),
    },
    findings: receiptFindings(input),
    outcome: input.decision.outcome,
    ...(input.termination ? { termination: input.termination } : {}),
    exitCode: exitCodeFor(input.termination ?? input.decision.outcome),
  };
  // Validate only this intentionally minimal projection, never the raw scan.
  assertSafeReceiptValue(base);
  const digest = digestFor(base);
  return { ...base, digest };
}
