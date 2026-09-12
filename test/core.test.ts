import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { fingerprint, dedupe, rank, postureLabel, countBySeverity } from "../src/core/finding.ts";
import { redact, redactValue, safeSnippet } from "../src/core/redact.ts";
import { editDistance } from "../src/scanners/_shared.ts";
import { inRegexLiteral, inComment, isClientReachable } from "../src/core/text.ts";
import type { Finding } from "../src/core/types.ts";

function mkFinding(over: Partial<Finding> = {}): Finding {
  return {
    id: "x",
    ruleId: "TEST-RULE",
    title: "t",
    description: "d",
    severity: "high",
    confidence: "high",
    provenance: "deterministic",
    source: "test",
    target: { kind: "repository", id: "/repo", label: "repo" },
    evidence: "e",
    exploit: "x",
    remediation: { summary: "s", steps: [] },
    mappings: {},
    tags: [],
    status: "open",
    firstSeenAt: "2026-01-01T00:00:00.000Z",
    lastSeenAt: "2026-01-01T00:00:00.000Z",
    ...over,
  };
}

/**
 * The fingerprint is a compatibility contract, not an implementation detail.
 * Every stored triage decision -- suppressed, false-positive, accepted risk --
 * is keyed on it. If these vectors ever change, every customer's triage history
 * silently detaches from its findings and previously-dismissed issues reappear.
 * Changing this algorithm requires a migration, not an edit.
 */
describe("fingerprint (stability contract)", () => {
  const VECTORS: [string, string, string | undefined, string, string][] = [
    ["SECRET-AWS-KEY", "/repo", "src/a.ts", "AWS key at src/a.ts:12", "5e2ce9067a3bd25e"],
    ["AIC-RLS-DISABLED", "/repo", "db.sql", "ALTER TABLE x DISABLE ROW LEVEL SECURITY", "0cd7ed258cea9135"],
    ["CODE-SQL-INJECTION", "/other", undefined, "query(`...`)", "ab249ad51172f66e"],
  ];

  test("known vectors do not change", () => {
    for (const [rule, target, file, evidence, expected] of VECTORS) {
      assert.equal(
        fingerprint(rule, target, file, evidence),
        expected,
        `fingerprint drifted for ${rule}. Every customer's triage history depends on this value.`,
      );
    }
  });

  test("is stable across whitespace, quoting and case changes", () => {
    const a = fingerprint("R", "/t", "f.ts", `const x = "secret"`);
    const b = fingerprint("R", "/t", "f.ts", `const   x =  'SECRET'`);
    assert.equal(a, b, "reformatting a line must not orphan its triage decision");
  });

  test("differs when the rule, target, file or evidence differs", () => {
    const base = fingerprint("R", "/t", "f.ts", "e");
    assert.notEqual(base, fingerprint("R2", "/t", "f.ts", "e"));
    assert.notEqual(base, fingerprint("R", "/t2", "f.ts", "e"));
    assert.notEqual(base, fingerprint("R", "/t", "g.ts", "e"));
    assert.notEqual(base, fingerprint("R", "/t", "f.ts", "e2"));
  });
});

describe("redaction", () => {
  test("never emits a usable AWS key", () => {
    const out = redact("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");
    assert.ok(!out.includes("AKIAIOSFODNN7EXAMPLE"));
    assert.match(out, /AKIA\*+MPLE/);
  });

  test("scrubs tokens, connection strings and private key blocks", () => {
    const cases = [
      "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
      "postgres://admin:hunter2@db.internal:5432/app",
      "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "https://user:pass@internal.example.com/hook",
    ];
    for (const secret of cases) {
      const out = redact(`value: ${secret}`);
      assert.ok(!out.includes(secret), `redact() leaked: ${secret}`);
    }
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----";
    assert.equal(redact(pem), "[REDACTED PRIVATE KEY BLOCK]");
  });

  test("short values are fully masked rather than partially revealed", () => {
    assert.equal(redactValue("abc"), "****");
    assert.ok(!redactValue("shortkey").includes("shortkey"));
  });

  test("snippets are length-capped and redacted", () => {
    const long = `key=${"A".repeat(500)}`;
    const out = safeSnippet(long, 80);
    assert.ok(out.length <= 84);
  });
});

describe("finding handling", () => {
  test("dedupe collapses identical ids and merges tags", () => {
    const a = mkFinding({ id: "same", severity: "medium", tags: ["a"] });
    const b = mkFinding({ id: "same", severity: "critical", tags: ["b"] });
    const out = dedupe([a, b]);
    assert.equal(out.length, 1);
    assert.equal(out[0].severity, "critical", "the worse severity must win");
    assert.deepEqual([...out[0].tags].sort(), ["a", "b"]);
  });

  test("rank orders worst first, deterministic before LLM", () => {
    const out = rank([
      mkFinding({ id: "1", severity: "low" }),
      mkFinding({ id: "2", severity: "critical", provenance: "llm-assisted" }),
      mkFinding({ id: "3", severity: "critical", provenance: "deterministic" }),
      mkFinding({ id: "4", severity: "medium" }),
    ]);
    assert.deepEqual(out.map((f) => f.id), ["3", "2", "4", "1"]);
  });

  test("posture never reports a score and never claims safety", () => {
    const clean = postureLabel(countBySeverity([]));
    assert.equal(clean.tone, "ok");
    assert.match(clean.detail, /not the same as being secure/i);
    assert.ok(!/\d+%/.test(clean.detail), "must never present a percentage");

    const bad = postureLabel(countBySeverity([mkFinding({ severity: "critical" })]));
    assert.equal(bad.tone, "critical");
  });
});

describe("text analysis", () => {
  test("edit distance treats an adjacent swap as one edit", () => {
    // Transposition is the most common typo and the most common squat shape.
    assert.equal(editDistance("lodahs", "lodash", 2), 1);
    assert.equal(editDistance("axois", "axios", 2), 1);
    assert.equal(editDistance("expres", "express", 2), 1);
    assert.equal(editDistance("lodash", "lodash", 2), 0);
    assert.ok(editDistance("react", "vue", 2) > 2);
  });

  test("regex literals are recognised so detectors do not flag themselves", () => {
    const src = `const re = /rejectUnauthorized\\s*:\\s*false/g;\nconst bad = { rejectUnauthorized: false };`;
    const inLiteral = src.indexOf("rejectUnauthorized");
    const inRealCode = src.lastIndexOf("rejectUnauthorized");
    assert.equal(inRegexLiteral(src, inLiteral), true, "pattern inside a regex literal must be ignored");
    assert.equal(inRegexLiteral(src, inRealCode), false, "real code must still be flagged");
  });

  test("comments are recognised", () => {
    const src = `// eval(userInput) would be bad\neval(userInput);`;
    assert.equal(inComment(src, src.indexOf("eval")), true);
    assert.equal(inComment(src, src.lastIndexOf("eval")), false);
  });

  test("client-reachable detection covers the use client directive", () => {
    assert.equal(isClientReachable("src/lib/x.ts", '"use client";\nexport const a = 1;'), true);
    assert.equal(isClientReachable("src/components/Button.tsx"), true);
    assert.equal(isClientReachable("src/lib/db.ts"), false);
  });
});
