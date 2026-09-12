import { createHash } from "node:crypto";
import type { Finding, RawFinding, Severity, Target } from "./types.ts";
import { redact, safeSnippet } from "./redact.ts";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[a] - SEVERITY_ORDER[b];
}

/**
 * Stable finding identity.
 *
 * The hard requirement is that the same real-world problem produces the same id
 * across scans, so that triage decisions (suppressed, false-positive, accepted
 * risk) survive a reformat, an import reorder, or twenty lines added above.
 * Line numbers are therefore deliberately NOT part of the fingerprint; a
 * normalized form of the matched evidence is used instead.
 */
export function fingerprint(
  ruleId: string,
  targetId: string,
  file: string | undefined,
  evidence: string,
): string {
  const normalized = evidence
    .toLowerCase()
    .replace(/\s+/g, " ")
    .replace(/['"`]/g, "")
    .trim();
  const h = createHash("sha256");
  h.update(`${ruleId} ${targetId} ${file ?? ""} ${normalized}`);
  return h.digest("hex").slice(0, 16);
}

/**
 * Promote a scanner's raw output into a canonical Finding: assign identity,
 * stamp provenance and time, and force every free-text field through redaction.
 */
export function materialize(
  raw: RawFinding,
  opts: {
    source: string;
    target: Target;
    now?: string;
    provenance?: RawFinding["provenance"];
  },
): Finding {
  const now = opts.now ?? new Date().toISOString();
  const evidence = redact(raw.evidence);
  const id = fingerprint(raw.ruleId, opts.target.id, raw.location?.file, raw.evidence);

  return {
    ...raw,
    id,
    source: opts.source,
    target: opts.target,
    provenance: raw.provenance ?? opts.provenance ?? "deterministic",
    description: redact(raw.description),
    evidence,
    exploit: redact(raw.exploit),
    location: raw.location
      ? {
          ...raw.location,
          snippet: raw.location.snippet ? safeSnippet(raw.location.snippet) : undefined,
        }
      : undefined,
    remediation: {
      ...raw.remediation,
      summary: redact(raw.remediation.summary),
      steps: raw.remediation.steps.map(redact),
      codeFix: raw.remediation.codeFix
        ? {
            ...raw.remediation.codeFix,
            before: raw.remediation.codeFix.before
              ? redact(raw.remediation.codeFix.before)
              : undefined,
            after: redact(raw.remediation.codeFix.after),
          }
        : undefined,
    },
    status: "open",
    firstSeenAt: now,
    lastSeenAt: now,
  };
}

const CONFIDENCE_ORDER = { confirmed: 0, high: 1, medium: 2, low: 3 } as const;
const PROVENANCE_ORDER = { deterministic: 0, hybrid: 1, "llm-assisted": 2 } as const;

/**
 * Collapse duplicates by id, keeping the highest-severity and highest-confidence
 * instance. Two scanners legitimately overlap (a hardcoded AWS key is both a
 * secret and a SAST finding) and the user should see it once.
 */
export function dedupe(findings: Finding[]): Finding[] {
  const byId = new Map<string, Finding>();
  for (const f of findings) {
    const existing = byId.get(f.id);
    if (!existing) {
      byId.set(f.id, { ...f, tags: [...f.tags] });
      continue;
    }
    const mergedTags = [...new Set([...existing.tags, ...f.tags])];
    const better =
      compareSeverity(f.severity, existing.severity) < 0 ||
      (f.severity === existing.severity &&
        CONFIDENCE_ORDER[f.confidence] < CONFIDENCE_ORDER[existing.confidence]);
    byId.set(f.id, { ...(better ? f : existing), tags: mergedTags });
  }
  return [...byId.values()];
}

/** Worst-first ordering: severity, then confidence, then deterministic before LLM. */
export function rank(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      compareSeverity(a.severity, b.severity) ||
      CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence] ||
      PROVENANCE_ORDER[a.provenance] - PROVENANCE_ORDER[b.provenance] ||
      a.ruleId.localeCompare(b.ruleId) ||
      (a.location?.file ?? "").localeCompare(b.location?.file ?? ""),
  );
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/**
 * Guardian-Unit-Penetration-Testing Agent never reports a single "security score" or "percent secure". A number
 * like that gets screenshotted into a board deck and read as a guarantee, and no
 * static scan can support that claim. What we report instead is a posture label
 * derived only from what was actually found, always shown next to the coverage
 * statement that says what was not checked.
 */
export function postureLabel(counts: Record<Severity, number>): {
  label: string;
  tone: "critical" | "warn" | "ok";
  detail: string;
} {
  if (counts.critical > 0) {
    return {
      label: "Act now",
      tone: "critical",
      detail: `${counts.critical} critical ${counts.critical === 1 ? "issue needs" : "issues need"} attention today.`,
    };
  }
  if (counts.high > 0) {
    return {
      label: "Fix this week",
      tone: "warn",
      detail: `${counts.high} high-severity ${counts.high === 1 ? "issue" : "issues"} found. No criticals.`,
    };
  }
  if (counts.medium > 0) {
    return {
      label: "Worth cleaning up",
      tone: "warn",
      detail: `${counts.medium} medium ${counts.medium === 1 ? "issue" : "issues"}. Nothing urgent.`,
    };
  }
  return {
    label: "Nothing found",
    tone: "ok",
    detail: "No issues matched the rules that ran. That is not the same as being secure.",
  };
}
