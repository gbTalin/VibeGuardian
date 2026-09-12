import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { configDir } from "./config.ts";
import { redact, redactForOutput } from "./redact.ts";
import type { Finding, FindingStatus, ScanResult } from "./types.ts";

/**
 * Local scan history and triage state.
 *
 * Uses node:sqlite -- built into Node, so Guardian-Unit-Penetration-Testing Agent ships with zero native
 * modules and zero npm dependencies. For a security tool that is not a
 * stylistic preference: every dependency is a supply-chain edge, and a scanner
 * with 400 transitive packages is asking its customers to trust 400 strangers.
 *
 * The database lives on the customer's disk and is never transmitted.
 */

export interface ScanSummaryRow {
  scanId: string;
  targetId: string;
  targetLabel: string;
  startedAt: string;
  durationMs: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export class Store {
  private db: DatabaseSync;

  constructor(dbPath?: string) {
    const path = dbPath ?? join(configDir(), "guardian-unit.db");
    mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec("PRAGMA foreign_keys = ON");
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        scan_id      TEXT PRIMARY KEY,
        target_id    TEXT NOT NULL,
        target_label TEXT NOT NULL,
        started_at   TEXT NOT NULL,
        finished_at  TEXT NOT NULL,
        duration_ms  INTEGER NOT NULL,
        version      TEXT NOT NULL,
        coverage     TEXT NOT NULL,
        warnings     TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS findings (
        scan_id   TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
        id        TEXT NOT NULL,
        rule_id   TEXT NOT NULL,
        severity  TEXT NOT NULL,
        file      TEXT,
        payload   TEXT NOT NULL,
        PRIMARY KEY (scan_id, id)
      );

      CREATE INDEX IF NOT EXISTS idx_findings_id ON findings(id);
      CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id, started_at DESC);

      -- Triage decisions live outside any single scan so they survive rescans.
      CREATE TABLE IF NOT EXISTS triage (
        finding_id TEXT PRIMARY KEY,
        target_id  TEXT NOT NULL,
        status     TEXT NOT NULL,
        note       TEXT,
        updated_at TEXT NOT NULL
      );
    `);
  }

  saveScan(result: ScanResult): void {
    const insertScan = this.db.prepare(`
      INSERT OR REPLACE INTO scans
        (scan_id, target_id, target_label, started_at, finished_at, duration_ms, version, coverage, warnings)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertFinding = this.db.prepare(`
      INSERT OR REPLACE INTO findings (scan_id, id, rule_id, severity, file, payload)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    this.db.exec("BEGIN");
    try {
      insertScan.run(
        result.scanId,
        redact(result.target.id),
        redact(result.target.label),
        result.startedAt,
        result.finishedAt,
        result.durationMs,
        result.guardianUnitVersion,
        JSON.stringify(redactForOutput(result.coverage)),
        JSON.stringify(redactForOutput(result.warnings)),
      );
      for (const f of result.findings) {
        insertFinding.run(
          result.scanId,
          f.id,
          f.ruleId,
          f.severity,
          f.location?.file ? redact(f.location.file) : null,
          JSON.stringify(redactForOutput(f)),
        );
      }
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  /** Apply stored triage decisions onto a fresh scan's findings. */
  applyTriage(findings: Finding[], targetId: string): Finding[] {
    const rows = this.db
      .prepare("SELECT finding_id, status, note FROM triage WHERE target_id = ?")
      .all(targetId) as { finding_id: string; status: string; note: string | null }[];
    const map = new Map(rows.map((r) => [r.finding_id, r]));
    return findings.map((f) => {
      const t = map.get(f.id);
      if (!t) return f;
      return { ...f, status: t.status as FindingStatus, note: t.note ? redact(t.note) : undefined };
    });
  }

  setTriage(findingId: string, targetId: string, status: FindingStatus, note?: string): void {
    this.db
      .prepare(
        `INSERT INTO triage (finding_id, target_id, status, note, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(finding_id) DO UPDATE SET status = excluded.status,
                                               note = excluded.note,
                                               updated_at = excluded.updated_at`,
      )
      .run(findingId, targetId, status, note ? redact(note) : null, new Date().toISOString());
  }

  recentScans(limit = 25): ScanSummaryRow[] {
    const rows = this.db
      .prepare(
        `SELECT s.scan_id, s.target_id, s.target_label, s.started_at, s.duration_ms,
                SUM(f.severity = 'critical') AS critical,
                SUM(f.severity = 'high')     AS high,
                SUM(f.severity = 'medium')   AS medium,
                SUM(f.severity = 'low')      AS low,
                SUM(f.severity = 'info')     AS info,
                COUNT(f.id)                  AS total
         FROM scans s LEFT JOIN findings f ON f.scan_id = s.scan_id
         GROUP BY s.scan_id
         ORDER BY s.started_at DESC
         LIMIT ?`,
      )
      .all(limit) as Record<string, unknown>[];
    return rows.map((r) => ({
      scanId: String(r.scan_id),
      targetId: String(r.target_id),
      targetLabel: String(r.target_label),
      startedAt: String(r.started_at),
      durationMs: Number(r.duration_ms),
      critical: Number(r.critical ?? 0),
      high: Number(r.high ?? 0),
      medium: Number(r.medium ?? 0),
      low: Number(r.low ?? 0),
      info: Number(r.info ?? 0),
      total: Number(r.total ?? 0),
    }));
  }

  findingsForScan(scanId: string): Finding[] {
    const rows = this.db
      .prepare("SELECT payload FROM findings WHERE scan_id = ?")
      .all(scanId) as { payload: string }[];
    return rows.map((r) => redactForOutput(JSON.parse(r.payload) as Finding));
  }

  /**
   * Compare a scan against the previous scan of the same target.
   * This is the rescan-verification loop: what got fixed, what is new, what
   * persists. "Fixed" here means "no longer detected", which is a weaker claim
   * than "fixed correctly" and the UI says so.
   */
  diffAgainstPrevious(result: ScanResult): {
    resolved: Finding[];
    introduced: Finding[];
    persisting: Finding[];
    previousScanId: string | null;
  } {
    const prev = this.db
      .prepare(
        `SELECT scan_id FROM scans WHERE target_id = ? AND scan_id != ?
         ORDER BY started_at DESC LIMIT 1`,
      )
      .get(result.target.id, result.scanId) as { scan_id: string } | undefined;

    if (!prev) {
      return {
        resolved: [],
        introduced: result.findings,
        persisting: [],
        previousScanId: null,
      };
    }
    const before = this.findingsForScan(prev.scan_id);
    const beforeIds = new Set(before.map((f) => f.id));
    const nowIds = new Set(result.findings.map((f) => f.id));
    return {
      resolved: before.filter((f) => !nowIds.has(f.id)),
      introduced: result.findings.filter((f) => !beforeIds.has(f.id)),
      persisting: result.findings.filter((f) => beforeIds.has(f.id)),
      previousScanId: prev.scan_id,
    };
  }

  close(): void {
    this.db.close();
  }
}
