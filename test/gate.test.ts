import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { decideRelease, exitCodeFor } from "../src/gate/policy.ts";
import { runGate } from "../src/gate/run.ts";
import type { GateFinding } from "../src/gate/types.ts";

const ROOT = resolve(import.meta.dirname, "..");

function open(
  severity: GateFinding["severity"],
  confidence: GateFinding["confidence"],
): GateFinding {
  return { id: `${severity}-${confidence}`, severity, confidence, status: "open" };
}

function runCli(args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, ["bin/guardian-unit.mjs", ...args], { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code) => resolveResult({ code, stdout, stderr }));
  });
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

  test("treats a refused probe as a distinct terminal result", async () => {
    const root = await mkdtemp(join(tmpdir(), "guardian-gate-refused-"));
    try {
      const result = await runGate({
        root,
        probe: { state: "REFUSED" },
        now: () => new Date("2026-09-12T18:00:02.000Z"),
      });
      assert.equal(result.decision.outcome, "HOLD");
      assert.equal(result.termination, "REFUSED");
      assert.equal(result.exitCode, 4);
      assert.equal(result.receipt.outcome, "HOLD");
      assert.equal(result.receipt.termination, "REFUSED");
      assert.equal(result.receipt.exitCode, 4);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("forces static gate scans offline even when saved config opts into network", async () => {
    const root = await mkdtemp(join(tmpdir(), "guardian-gate-static-"));
    const home = await mkdtemp(join(tmpdir(), "guardian-gate-home-"));
    const previous = process.env.GUARDIAN_UNIT_HOME;
    process.env.GUARDIAN_UNIT_HOME = home;
    try {
      await writeFile(join(home, "config.json"), JSON.stringify({ allowNetwork: true }));
      const result = await runGate({ root, now: () => new Date("2026-09-12T18:00:02.000Z") });
      assert.ok(result.scan.coverage.limitations.some((line) => /Network checks were disabled/.test(line)));
      assert.equal(result.decision.outcome, "PASS");
    } finally {
      if (previous === undefined) delete process.env.GUARDIAN_UNIT_HOME;
      else process.env.GUARDIAN_UNIT_HOME = previous;
      await rm(root, { recursive: true, force: true });
      await rm(home, { recursive: true, force: true });
    }
  });

  test("gate emits one JSON refusal document and non-gate failures retain exit 2", async () => {
    const root = await mkdtemp(join(tmpdir(), "guardian-gate-cli-"));
    try {
      const refused = await runCli(["gate", root, "--target", "https://example.com", "--json"]);
      assert.equal(refused.code, 4);
      assert.equal(refused.stdout.trim().split("\n").length, 1);
      assert.deepEqual(JSON.parse(refused.stdout), {
        outcome: "HOLD",
        termination: "REFUSED",
        exitCode: 4,
        message: "REFUSED: --target and --authorization must be supplied together.",
      });

      const artifactFailure = await runCli(["gate", root, "--receipt", root, "--json"]);
      assert.equal(artifactFailure.code, 5);
      assert.equal(artifactFailure.stdout.trim().split("\n").length, 1);
      const artifactError = JSON.parse(artifactFailure.stdout);
      assert.equal(artifactError.termination, "ERROR");
      assert.equal(artifactError.exitCode, 5);
      assert.equal("receipt" in artifactError, false, "must not emit a success receipt before an artifact failure");

      const nonGateFailure = await runCli(["ui", "--port", "99999", "--no-open"]);
      assert.equal(nonGateFailure.code, 2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
