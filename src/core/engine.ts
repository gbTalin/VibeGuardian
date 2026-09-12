import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import type {
  CoverageReport,
  Finding,
  Scanner,
  ScanContext,
  ScanResult,
  Target,
} from "./types.ts";
import { dedupe, materialize, rank } from "./finding.ts";
import { looksBinary, readIgnoreFile, walk } from "./walk.ts";
import type { GuardianUnitConfig } from "./config.ts";
import { VERSION } from "../version.ts";

export interface EngineOptions {
  config: GuardianUnitConfig;
  /** Restrict to these scanner names. Empty means all applicable. */
  only?: string[];
  /** Exclude these scanner names. */
  skip?: string[];
  onProgress?: (msg: string, fraction?: number) => void;
  signal?: AbortSignal;
  maxFiles?: number;
}

/**
 * The always-visible limitations statement.
 *
 * This is a product decision, not boilerplate. Every report Guardian-Unit-Penetration-Testing Agent produces
 * carries it. Static analysis of code at rest cannot see runtime behaviour,
 * cannot test a live system, and cannot stop a phishing email. Saying so
 * plainly is what makes the findings we DO report credible.
 */
export function baseLimitations(cfg: GuardianUnitConfig, networkUsed: boolean): string[] {
  const limits = [
    "This is a static analysis of code and configuration at rest. It cannot observe running systems, live traffic, or user behaviour.",
    "It does not test a deployed application. A finding here is a code-level defect, not a proven live exploit, unless explicitly marked as verified.",
    "It cannot prevent phishing, social engineering, credential reuse, or physical compromise. It reduces the blast radius of those attacks; it does not block them.",
    "It sees only files it could read. Anything excluded by ignore rules, size limits, or permissions was not examined.",
    "Absence of findings is not evidence of security. It means the rules that ran did not match.",
  ];
  if (!networkUsed) {
    limits.push(
      "Network checks were disabled, so no external surface, TLS, DNS, or live advisory lookup was performed.",
    );
  }
  if (cfg.provider.kind === "none") {
    limits.push(
      "No model was configured, so no agent reasoning ran. Only deterministic rules were applied.",
    );
  } else if (cfg.provider.tier === "small") {
    limits.push(
      "Agent analysis used a small local model. Its reasoning is materially weaker than a frontier model and its conclusions need human review.",
    );
  }
  return limits;
}

export class Engine {
  private scanners: Scanner[] = [];

  register(...scanners: Scanner[]): this {
    for (const s of scanners) {
      if (this.scanners.some((x) => x.name === s.name)) {
        throw new Error(`Duplicate scanner name: ${s.name}`);
      }
      this.scanners.push(s);
    }
    return this;
  }

  list(): Scanner[] {
    return [...this.scanners];
  }

  ruleCount(): number {
    return this.scanners.reduce((n, s) => n + s.rules.length, 0);
  }

  async scan(targetPath: string, opts: EngineOptions): Promise<ScanResult> {
    const started = Date.now();
    const startedAt = new Date().toISOString();
    const root = resolve(targetPath);
    const cfg = opts.config;
    const progress = opts.onProgress ?? (() => {});
    const warnings: string[] = [];

    const target: Target = {
      kind: "repository",
      id: root,
      label: root.split("/").filter(Boolean).pop() ?? root,
    };

    progress("Finding files to scan", 0.02);
    const extraIgnores = await readIgnoreFile(root);
    const walked = await walk(root, {
      extraIgnores,
      signal: opts.signal,
      maxFiles: opts.maxFiles,
    });
    progress(`Found ${walked.files.length} files`, 0.08);

    // One read per file for the whole scan, shared across every scanner.
    // Repos are read-heavy and re-reading per scanner is the difference between
    // a 6-second scan and a 60-second one.
    const cache = new Map<string, string | null>();
    const read = async (rel: string): Promise<string | null> => {
      if (cache.has(rel)) return cache.get(rel)!;
      let text: string | null = null;
      try {
        const buf = await readFile(join(root, rel));
        text = looksBinary(buf) ? null : buf.toString("utf8");
      } catch {
        text = null;
      }
      cache.set(rel, text);
      return text;
    };

    const networkAllowed = cfg.allowNetwork === true;
    const ctxBase = {
      root,
      target,
      files: walked.files,
      read,
      networkAllowed,
      signal: opts.signal ?? new AbortController().signal,
    };

    const selected = this.scanners.filter((s) => {
      if (opts.only?.length && !opts.only.includes(s.name)) return false;
      if (opts.skip?.includes(s.name)) return false;
      return true;
    });

    const scannersRun: string[] = [];
    const scannersSkipped: { name: string; reason: string }[] = [];
    const collected: Finding[] = [];

    let done = 0;
    const total = Math.max(selected.length, 1);

    // Scanners are independent and mostly I/O bound over a shared cache, so they
    // run concurrently. Errors are contained: one broken scanner degrades
    // coverage, it never fails the scan.
    await Promise.all(
      selected.map(async (scanner) => {
        const ctx: ScanContext = {
          ...ctxBase,
          progress: (m, f) => progress(`${scanner.title}: ${m}`, f),
        };
        try {
          if (scanner.requiresNetwork && !networkAllowed) {
            scannersSkipped.push({
              name: scanner.name,
              reason: "needs network access, which is off by default",
            });
            return;
          }
          if (!(await scanner.appliesTo(ctx))) {
            scannersSkipped.push({
              name: scanner.name,
              reason: "nothing in this target matches what it checks",
            });
            return;
          }
          const raws = await scanner.scan(ctx);
          for (const raw of raws) {
            collected.push(materialize(raw, { source: scanner.name, target }));
          }
          scannersRun.push(scanner.name);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          warnings.push(`Scanner "${scanner.name}" failed and was skipped: ${msg}`);
          scannersSkipped.push({ name: scanner.name, reason: `error: ${msg}` });
        } finally {
          done++;
          progress(`Ran ${done} of ${total} checks`, 0.08 + 0.85 * (done / total));
        }
      }),
    );

    const suppressed = new Set(
      cfg.suppressions.filter((s) => !s.path).map((s) => s.ruleId),
    );
    const pathSuppressions = cfg.suppressions.filter((s) => s.path);

    const kept = dedupe(collected).filter((f) => {
      if (suppressed.has(f.ruleId)) return false;
      return !pathSuppressions.some(
        (s) => s.ruleId === f.ruleId && f.location?.file?.startsWith(s.path!),
      );
    });

    const coverage: CoverageReport = {
      filesScanned: walked.files.length,
      filesSkipped: walked.skipped,
      skipReasons: walked.skipReasons,
      scannersRun: scannersRun.sort(),
      scannersSkipped: scannersSkipped.sort((a, b) => a.name.localeCompare(b.name)),
      agentAnalysisRan: false,
      limitations: baseLimitations(cfg, networkAllowed),
    };

    progress("Done", 1);
    const finishedAt = new Date().toISOString();
    return {
      scanId: randomUUID(),
      target,
      startedAt,
      finishedAt,
      durationMs: Date.now() - started,
      findings: rank(kept),
      coverage,
      warnings,
      guardianUnitVersion: VERSION,
    };
  }
}
