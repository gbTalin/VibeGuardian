import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { buildReceipt, canonicalJson } from "../src/gate/receipt.ts";
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
});
