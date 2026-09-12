/** Re-exports and small helpers every scanner reaches for. */

export {
  lineOf,
  matches,
  inComment,
  inRegexLiteral,
  extname,
  basename,
  isClientReachable,
  isServerOnly,
  isTestFile,
  languageOf,
} from "../core/text.ts";

import { languageOf } from "../core/text.ts";

/** Language hint for a remediation snippet, defaulting to something a fence can render. */
export function safeLang(file: string): string {
  const l = languageOf(file);
  return l === "text" ? "typescript" : l;
}

/** Parse JSON leniently; returns null instead of throwing, since scanners must not crash on bad input. */
export function tryJson<T = unknown>(text: string): T | null {
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

/**
 * Minimal YAML reader for the flat, predictable subset that CI and Kubernetes
 * manifests actually use. A full YAML parser is a dependency and, historically,
 * a source of remote code execution in its own right; scanners here work on the
 * text and on this shallow view, never on arbitrary deserialization.
 */
export function yamlKeyLines(text: string): { key: string; value: string; line: number; indent: number }[] {
  const out: { key: string; value: string; line: number; indent: number }[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw || /^\s*#/.test(raw)) continue;
    const m = /^(\s*)(?:-\s*)?([A-Za-z0-9_.-]+)\s*:\s*(.*)$/.exec(raw);
    if (!m) continue;
    out.push({
      indent: m[1].length,
      key: m[2],
      value: m[3].replace(/\s+#.*$/, "").trim().replace(/^['"]|['"]$/g, ""),
      line: i + 1,
    });
  }
  return out;
}

/** Compare two dotted or semver-ish versions. Returns -1, 0, or 1. */
export function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^[^0-9]*/, "").split(/[.\-+]/);
  const pb = b.replace(/^[^0-9]*/, "").split(/[.\-+]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = Number.parseInt(pa[i] ?? "0", 10);
    const nb = Number.parseInt(pb[i] ?? "0", 10);
    if (Number.isNaN(na) || Number.isNaN(nb)) {
      const sa = pa[i] ?? "";
      const sb = pb[i] ?? "";
      if (sa === sb) continue;
      return sa < sb ? -1 : 1;
    }
    if (na !== nb) return na < nb ? -1 : 1;
  }
  return 0;
}

/**
 * Damerau-Levenshtein distance (optimal string alignment), capped for speed.
 *
 * The transposition term matters more than it looks. Plain Levenshtein scores a
 * swapped pair of adjacent letters as two edits, but transposition is the single
 * most common human typo and the most common squat shape: "lodahs" for "lodash",
 * "axois" for "axios". Scoring those as distance 1 is what makes a
 * one-edit typosquat threshold actually catch typosquats.
 */
export function editDistance(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  // Three rolling rows: i-2, i-1, and the current row.
  let prev2 = new Array<number>(b.length + 1).fill(0);
  let prev = new Array<number>(b.length + 1);
  let cur = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;

  for (let i = 1; i <= a.length; i++) {
    cur[0] = i;
    let rowMin = cur[0];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, prev2[j - 2] + 1);
      }
      cur[j] = v;
      rowMin = Math.min(rowMin, v);
    }
    if (rowMin > max) return max + 1;
    const spare = prev2;
    prev2 = prev;
    prev = cur;
    cur = spare;
  }
  return prev[b.length];
}
