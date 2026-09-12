import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { decideRelease, exitCodeFor } from "../src/gate/policy.ts";
import type { GateFinding } from "../src/gate/types.ts";

function open(
  severity: GateFinding["severity"],
  confidence: GateFinding["confidence"],
): GateFinding {
  return { id: `${severity}-${confidence}`, severity, confidence, status: "open" };
}

describe("release policy", () => {
  test("applies the required deployment decision matrix", () => {
    assert.equal(decideRelease({ findings: [open("critical", "confirmed")], requiredFailures: [] }).outcome, "BLOCK");
    assert.equal(decideRelease({ findings: [open("medium", "confirmed")], requiredFailures: [] }).outcome, "WARN");
    assert.equal(decideRelease({ findings: [], requiredFailures: ["probe timeout"] }).outcome, "HOLD");
    assert.equal(decideRelease({ findings: [], requiredFailures: [] }).outcome, "PASS");
    assert.equal(decideRelease({ findings: [open("high", "unproven")], requiredFailures: [] }).outcome, "WARN");
  });

  test("blocks high-confidence open findings at the configured threshold", () => {
    const decision = decideRelease({
      findings: [open("medium", "high")],
      requiredFailures: [],
      policy: { blockAtOrAbove: "medium" },
    });
    assert.equal(decision.outcome, "BLOCK");
    assert.deepEqual(decision.blockingFindings, ["medium-high"]);
  });

  test("has a stable, non-overloaded exit contract", () => {
    assert.equal(exitCodeFor("PASS"), 0);
    assert.equal(exitCodeFor("BLOCK"), 1);
    assert.equal(exitCodeFor("WARN"), 2);
    assert.equal(exitCodeFor("HOLD"), 3);
    assert.equal(exitCodeFor("REFUSED"), 4);
    assert.equal(exitCodeFor("ERROR"), 5);
  });
});
