#!/usr/bin/env node
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const run = promisify(execFile);
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const launcher = resolve(packageRoot, "bin/guardian-unit.mjs");
const cleanApp = resolve(packageRoot, "examples/clean-app");

function listen(server) {
  return new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolveListen(server.address()));
  });
}

function close(server) {
  return new Promise((resolveClose) => server.close(() => resolveClose()));
}

function demoApp() {
  return createServer((request, response) => {
    response.setHeader("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("x-frame-options", "DENY");
    response.setHeader("referrer-policy", "no-referrer");
    response.setHeader("permissions-policy", "camera=(), microphone=(), geolocation=()");
    response.setHeader("cache-control", "no-store");
    response.setHeader("set-cookie", "guardian_demo=ready; HttpOnly; Secure; SameSite=Strict");

    if (request.method === "OPTIONS") {
      response.writeHead(204);
      response.end();
      return;
    }
    if (request.url === "/.well-known/security.txt") {
      response.setHeader("content-type", "text/plain; charset=utf-8");
      response.end("Contact: mailto:security@example.invalid\nExpires: 2030-01-01T00:00:00Z\n");
      return;
    }
    if (request.url === "/robots.txt") {
      response.setHeader("content-type", "text/plain; charset=utf-8");
      response.end("User-agent: *\nDisallow:\n");
      return;
    }
    response.setHeader("content-type", "text/html; charset=utf-8");
    response.end("<!doctype html><title>Guardian-Unit demo</title><h1>Ready</h1>");
  });
}

async function main() {
  const server = demoApp();
  let scratch;
  let exitCode = 5;
  try {
    const address = await listen(server);
    if (!address || typeof address === "string") throw new Error("Could not allocate the local demo port.");
    const origin = `http://127.0.0.1:${address.port}`;
    const now = new Date();
    const approval = {
      schemaVersion: 1,
      targets: [{
        origin,
        environment: "local",
        owner: "guardian-unit-demo",
        issuedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + 10 * 60 * 1000).toISOString(),
        requestBudget: 4,
        maxRedirects: 1,
        timeoutMs: 3000,
        ratePerSecond: 10,
        corsPreflight: false,
        approvedPaths: [],
      }],
    };

    scratch = await mkdtemp(resolve(tmpdir(), "guardian-unit-demo-"));
    const authorization = resolve(scratch, "targets.json");
    await writeFile(authorization, `${JSON.stringify(approval, null, 2)}\n`, "utf8");

    console.log("\nGuardian-Unit core demo");
    console.log("  1. Inspecting safe example source");
    console.log(`  2. Probing authorized loopback app at ${origin}`);
    console.log("  3. Producing a release decision and evidence receipt\n");

    try {
      const result = await run(
        process.execPath,
        [launcher, "gate", cleanApp, "--target", origin, "--authorization", authorization, "--json"],
        { cwd: packageRoot, maxBuffer: 10 * 1024 * 1024 },
      );
      const parsed = JSON.parse(result.stdout);
      validateResult(parsed);
      exitCode = Number(parsed.exitCode ?? 0);
      printSummary(parsed);
    } catch (error) {
      const stdout = typeof error?.stdout === "string" ? error.stdout : "";
      if (!stdout.trim()) throw error;
      const parsed = JSON.parse(stdout);
      validateResult(parsed);
      exitCode = Number(parsed.exitCode ?? error?.code ?? 5);
      printSummary(parsed);
    }
  } finally {
    if (server.listening) await close(server);
    if (scratch) await rm(scratch, { recursive: true, force: true });
  }
  process.exitCode = exitCode;
}

function validateResult(result) {
  const outcome = result?.decision?.outcome ?? result?.outcome;
  if (!["PASS", "WARN", "HOLD", "BLOCK"].includes(outcome) || !Number.isInteger(result?.exitCode)) {
    throw new Error("release gate returned malformed evidence");
  }
}

function printSummary(result) {
  const outcome = result.decision?.outcome ?? result.outcome ?? "HOLD";
  const findings = result.scan?.findings?.length ?? result.receipt?.findings?.length ?? 0;
  const probeState = result.probe?.state ?? result.receipt?.probe?.state ?? (result.termination === "REFUSED" ? "REFUSED" : "UNPROVEN");
  console.log(`  OUTCOME     ${outcome}`);
  console.log(`  SOURCE      ${findings} finding${findings === 1 ? "" : "s"}`);
  console.log(`  LIVE PROBE  ${probeState}`);
  console.log(`  EXIT        ${result.exitCode ?? "UNPROVEN"}`);
  if (result.receipt?.digest) console.log(`  RECEIPT     ${result.receipt.digest}`);
  for (const reason of result.decision?.reasons ?? []) console.log(`  REASON      ${reason}`);
  console.log("");
}

await main().catch((error) => {
  console.error(`Guardian-Unit demo failed safely: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 5;
});
