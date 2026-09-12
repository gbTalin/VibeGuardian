import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { buildReceipt, canonicalJson, sha256 } from "../src/gate/receipt.ts";
import { decideRelease } from "../src/gate/policy.ts";
import type { ScanResult } from "../src/core/types.ts";

function scan(metadata: Record<string, unknown>): ScanResult {
  return {
    scanId: "scan-1",
    target: { kind: "repository", id: "/private/repo", label: "repo" },
    startedAt: "2026-09-12T18:00:00.000Z",
    finishedAt: "2026-09-12T18:00:01.000Z",
    durationMs: 1000,
    findings: [],
    coverage: {
      filesScanned: 1,
      filesSkipped: 0,
      skipReasons: metadata as Record<string, number>,
      scannersRun: ["code"],
      scannersSkipped: [],
      agentAnalysisRan: false,
      limitations: [],
    },
    warnings: [],
    guardianUnitVersion: "0.1.0",
  };
}

describe("release receipt", () => {
  test("canonicalizes equivalent inputs and produces the same digest", () => {
    const input = {
      generatedAt: "2026-09-12T18:00:02.000Z",
      scan: scan({ beta: 2, alpha: 1 }),
      decision: decideRelease({ findings: [], requiredFailures: [] }),
      commit: { dirty: false, sha: "abc123" },
      policy: { version: "v1", digest: "policy-digest" },
      rules: { version: "v1", digest: "rules-digest" },
      runtime: { version: "0.1.0", digest: "runtime-digest" },
    };
    const equivalent = {
      runtime: { digest: "runtime-digest", version: "0.1.0" },
      rules: { digest: "rules-digest", version: "v1" },
      policy: { digest: "policy-digest", version: "v1" },
      commit: { sha: "abc123", dirty: false },
      decision: decideRelease({ requiredFailures: [], findings: [] }),
      scan: scan({ alpha: 1, beta: 2 }),
      generatedAt: "2026-09-12T18:00:02.000Z",
    };

    const a = buildReceipt(input);
    const b = buildReceipt(equivalent);
    assert.equal(canonicalJson(a), canonicalJson(b));
    assert.equal(a.digest, b.digest);
    assert.ok(!canonicalJson(a).includes("/private/repo"));
  });

  test("rejects secret-bearing keys before receipt creation", () => {
    for (const key of ["secret", "token", "authorization", "cookie", "responseBody"]) {
      assert.throws(() => canonicalJson({ [key]: "must not appear" }), /unsafe receipt key/i);
    }
  });

  test("uses code-unit key ordering and recomputes the digest from the unsigned receipt", () => {
    assert.equal(canonicalJson({ z: 1, "Ä": 2, a: 3, A: 4, "!": 5 }), '{"!":5,"A":4,"a":3,"z":1,"Ä":2}');
    assert.equal(canonicalJson({ "2": "two", "10": "ten", "1": "one" }), '{"1":"one","10":"ten","2":"two"}');
    const receipt = buildReceipt({
      generatedAt: "2026-09-12T18:00:02.000Z",
      scan: scan({}),
      decision: decideRelease({ findings: [], requiredFailures: [] }),
    });
    const { digest, ...unsigned } = receipt;
    assert.equal(digest, sha256(canonicalJson(unsigned)));
  });

  test("projects raw scanner input without exposing secrets or absolute paths", () => {
    const raw = scan({ "/Users/alice/repo/private": 1, "C:\\Users\\alice\\repo": 2, "\\\\server\\share\\repo": 3 });
    raw.coverage.scannersSkipped = [{ name: "code", reason: "failed at C:\\Users\\alice\\repo\\src\\x.ts" }];
    raw.coverage.limitations = ["See /Users/alice/repo/.guardianignore", "UNC \\\\server\\share\\logs", "file:///Users/alice/repo/config"];
    raw.warnings = ["warning at /Users/alice/repo/.env with AKIAIOSFODNN7EXAMPLE"];
    raw.findings = [
      {
        id: "fingerprint",
        severity: "high",
        confidence: "high",
        status: "open",
        location: { file: "C:\\Users\\alice\\repo\\src\\file.ts", startLine: 1, endLine: 1 },
        evidence: "cookie=session=super-secret-value AKIAIOSFODNN7EXAMPLE",
        description: "raw response body must not enter the receipt",
      },
    ] as ScanResult["findings"];
    const receipt = buildReceipt({
      generatedAt: "2026-09-12T18:00:02.000Z",
      scan: raw,
      decision: decideRelease({ findings: [], requiredFailures: [] }),
    });
    const output = canonicalJson(receipt);
    assert.ok(!/\/Users\/alice|C:\\Users|\\\\server|file:\/\/\/Users|AKIAIOSFODNN7EXAMPLE|super-secret-value/.test(output));
    assert.equal(receipt.findings[0].file, "src/file.ts");
  });

  test("rejects parent traversal but accepts names beginning with two dots", () => {
    const parent = scan({});
    parent.findings = [{ id: "parent", severity: "low", confidence: "low", status: "open", location: { file: "../outside.ts", startLine: 1, endLine: 1 } }] as ScanResult["findings"];
    assert.throws(
      () => buildReceipt({ generatedAt: "2026-09-12T18:00:02.000Z", scan: parent, decision: decideRelease({ findings: [], requiredFailures: [] }) }),
      /relative/i,
    );

    const valid = scan({});
    valid.findings = [{ id: "dots", severity: "low", confidence: "low", status: "open", location: { file: "..notes/check.ts", startLine: 1, endLine: 1 } }] as ScanResult["findings"];
    const receipt = buildReceipt({ generatedAt: "2026-09-12T18:00:02.000Z", scan: valid, decision: decideRelease({ findings: [], requiredFailures: [] }) });
    assert.equal(receipt.findings[0].file, "..notes/check.ts");
  });

  test("projects POSIX, Windows-drive, and UNC finding paths to relative context", () => {
    const cases = [
      ["/private/alice/repository/src/posix.ts", "src/posix.ts"],
      ["D:\\work\\repository\\src\\windows.ts", "src/windows.ts"],
      ["\\\\server\\share\\repository\\src\\unc.ts", "src/unc.ts"],
    ];
    for (const [path, expected] of cases) {
      const raw = scan({});
      raw.findings = [{ id: `path-${expected}`, severity: "low", confidence: "low", status: "open", location: { file: path, startLine: 1, endLine: 1 } }] as ScanResult["findings"];
      const receipt = buildReceipt({ generatedAt: "2026-09-12T18:00:02.000Z", scan: raw, decision: decideRelease({ findings: [], requiredFailures: [] }) });
      assert.equal(receipt.findings[0].file, expected);
    }
  });

  test("scrubs absolute paths embedded after punctuation delimiters in receipt text", () => {
    const raw = scan({
      "path=/Users/alice/repo/file.ts": 1,
      "path=C:\\Users\\alice\\repo\\file.ts": 1,
      "path=\\\\server\\share\\repo\\file.ts": 1,
    });
    raw.warnings = [
      "path=/Users/alice/repo/file.ts",
      "path=C:\\Users\\alice\\repo\\file.ts",
      "path=\\\\server\\share\\repo\\file.ts",
      "details:[/Users/alice/repo/file.ts]",
      "details:(C:\\Users\\alice\\repo\\file.ts)",
    ];
    raw.coverage.limitations = ["origin=\\\\server\\share\\repo\\file.ts"];
    const receipt = buildReceipt({
      generatedAt: "2026-09-12T18:00:02.000Z",
      scan: raw,
      decision: decideRelease({ findings: [], requiredFailures: [] }),
    });
    const output = canonicalJson(receipt);
    assert.doesNotMatch(output, /\/Users\/alice|C:\\Users|\\\\server/);
    assert.match(output, /\[path:repo\/file\.ts\]/);
  });

  test("scrubs diagnostic-looking absolute finding locations before relative normalization", () => {
    const cases = [
      "path=/Users/alice/repo/file.ts",
      "path=C:\\Users\\alice\\repo\\file.ts",
      "path=\\\\server\\share\\repo\\file.ts",
    ];
    for (const file of cases) {
      const raw = scan({});
      raw.findings = [{ id: file, severity: "low", confidence: "low", status: "open", location: { file, startLine: 1, endLine: 1 } }] as ScanResult["findings"];
      const receipt = buildReceipt({ generatedAt: "2026-09-12T18:00:02.000Z", scan: raw, decision: decideRelease({ findings: [], requiredFailures: [] }) });
      const output = canonicalJson(receipt);
      assert.doesNotMatch(output, /\/Users\/alice|C:\\Users|\\\\server/);
      assert.equal(receipt.findings[0].file, "path=[path:repo/file.ts]");
    }
    const normal = scan({});
    normal.findings = [{ id: "normal", severity: "low", confidence: "low", status: "open", location: { file: "src/components/file.ts", startLine: 1, endLine: 1 } }] as ScanResult["findings"];
    const normalReceipt = buildReceipt({ generatedAt: "2026-09-12T18:00:02.000Z", scan: normal, decision: decideRelease({ findings: [], requiredFailures: [] }) });
    assert.equal(normalReceipt.findings[0].file, "src/components/file.ts");
  });
});
