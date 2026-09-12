import { createHash } from "node:crypto";
import { isAbsolute, normalize } from "node:path";
import { redact } from "../core/redact.ts";
import { exitCodeFor } from "./policy.ts";
import type { EvidenceDigest, ReceiptFinding, ReceiptInput, ReleaseReceipt } from "./types.ts";

const UNSAFE_RECEIPT_KEY = /(secret|token|authorization|cookie|responsebody)/i;

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

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

function sortJson(value: unknown): JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Receipt values must be finite JSON numbers.");
    return value;
  }
  if (Array.isArray(value)) return value.map(sortJson);
  if (!value || typeof value !== "object") throw new Error("Receipt values must be JSON-compatible.");
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, entry]) => [key, sortJson(entry)]),
  ) as JsonValue;
}

/** Canonical JSON: recursively sorted object keys with no whitespace. */
export function canonicalJson(value: unknown): string {
  assertSafeReceiptValue(value);
  return JSON.stringify(sortJson(value));
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

function relativePath(value: string | undefined): string | undefined {
  if (!value) return undefined;
  if (isAbsolute(value) || normalize(value).startsWith("..")) {
    throw new Error("Receipt finding paths must be relative to the scan root.");
  }
  return value.replaceAll("\\", "/");
}

function receiptFindings(input: ReceiptInput): ReceiptFinding[] {
  const blocking = new Set(input.decision.blockingFindings);
  const warnings = new Set(input.decision.warningFindings);
  return input.scan.findings
    .map((finding) => ({
      fingerprint: finding.id,
      severity: finding.severity,
      confidence: finding.confidence,
      status: finding.status,
      disposition: blocking.has(finding.id) ? "BLOCK" : warnings.has(finding.id) ? "WARN" : "NONE",
      ...(finding.location?.file ? { file: relativePath(finding.location.file) } : {}),
    }))
    .sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
}

function defaultDigest(version: string, label: string): EvidenceDigest {
  return { version, digest: sha256(`${label}:${version}`) };
}

/**
 * Build a minimal, redacted receipt. It deliberately derives its finding
 * summary rather than copying finding evidence, snippets, URLs, or headers.
 */
export function buildReceipt(input: ReceiptInput): ReleaseReceipt {
  assertSafeReceiptValue(input);
  const runtime = input.runtime ?? defaultDigest(input.scan.guardianUnitVersion, "runtime");
  const rules = input.rules ?? defaultDigest(input.scan.guardianUnitVersion, "rules");
  const policy = input.policy ?? { version: input.decision.policy.version, digest: digestFor(input.decision.policy) };
  const intelligence = input.intelligence ?? { state: "UNPROVEN" as const };
  const commit = input.commit ?? { sha: "UNPROVEN", dirty: true };
  const base = {
    schemaVersion: 1 as const,
    generatedAt: normalizeIsoUtc(input.generatedAt, "generatedAt"),
    runtime,
    rules,
    policy,
    intelligence: {
      ...intelligence,
      ...(intelligence.checkedAt ? { checkedAt: normalizeIsoUtc(intelligence.checkedAt, "intelligence.checkedAt") } : {}),
    },
    ...(input.approval ? { approval: input.approval } : {}),
    commit,
    scan: {
      id: input.scan.scanId,
      startedAt: normalizeIsoUtc(input.scan.startedAt, "scan.startedAt"),
      finishedAt: normalizeIsoUtc(input.scan.finishedAt, "scan.finishedAt"),
      coverage: input.scan.coverage,
      warnings: [...input.scan.warnings].sort(),
    },
    findings: receiptFindings(input),
    outcome: input.decision.outcome,
    exitCode: exitCodeFor(input.decision.outcome),
  };
  const digest = digestFor(base);
  return { ...base, digest };
}
