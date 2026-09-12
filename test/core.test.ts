import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile as execFileCallback, spawn } from "node:child_process";
import { promisify } from "node:util";
import { createServer } from "node:net";
import { fingerprint, dedupe, rank, postureLabel, countBySeverity } from "../src/core/finding.ts";
import { redact, redactForOutput, redactValue, safeJson, safeSnippet } from "../src/core/redact.ts";
import { editDistance } from "../src/scanners/_shared.ts";
import { inRegexLiteral, inComment, isClientReachable } from "../src/core/text.ts";
import { buildEngine } from "../src/scanners/index.ts";
import { configDir } from "../src/core/config.ts";
import { Store } from "../src/core/store.ts";
import { toMarkdown } from "../src/report/markdown.ts";
import { toTerminal } from "../src/report/markdown.ts";
import { toSarif } from "../src/report/sarif.ts";
import { makeProvider } from "../src/agents/providers.ts";
import { formatMcpDiagnostic, serializeMcpMessage } from "../src/server/mcp.ts";
import { PRODUCT } from "../src/version.ts";
import type { Finding } from "../src/core/types.ts";

const execFile = promisify(execFileCallback);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function within<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolveWithin, rejectWithin) => {
    const timer = setTimeout(() => rejectWithin(new Error(`${label} timed out after ${ms}ms`)), ms);
    promise.then(
      (value) => { clearTimeout(timer); resolveWithin(value); },
      (error) => { clearTimeout(timer); rejectWithin(error); },
    );
  });
}

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const port = (server.address() as { port: number }).port;
  await new Promise<void>((done) => server.close(() => done()));
  return port;
}

async function childOutput(args: string[], input: string, env: NodeJS.ProcessEnv): Promise<string> {
  return new Promise((resolveOutput, reject) => {
    const child = spawn(process.execPath, args, { cwd: ROOT, env, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (chunk) => { out += chunk; });
    child.stderr.on("data", (chunk) => { err += chunk; });
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? resolveOutput(out) : reject(new Error(`child ${code}: ${err}`)));
    child.stdin.end(input);
  });
}

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

  test("redacts nested output fields at the serialization boundary", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const output = safeJson({ warning: `provider echoed ${secret}`, nested: { note: secret } }, 2);
    assert.ok(!output.includes(secret));
    assert.ok(!JSON.stringify(redactForOutput({ secret })).includes(secret));
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

describe("Guardian-Unit-Penetration-Testing Agent integration contracts", () => {
  test("ships only static scanners and no legacy live surface module", async () => {
    assert.deepEqual(
      buildEngine().list().map((scanner) => scanner.name),
      ["secrets", "ai-code", "ai-agents", "dependencies", "ci", "iac", "code"],
    );
    await assert.rejects(access(join(ROOT, "src/scanners/surface.ts"), constants.F_OK));
  });

  test("uses Guardian-Unit-Penetration-Testing Agent home and ignore paths", async () => {
    const previous = process.env.GUARDIAN_UNIT_HOME;
    process.env.GUARDIAN_UNIT_HOME = "/tmp/guardian-unit-test-home";
    try {
      assert.equal(configDir(), "/tmp/guardian-unit-test-home");
      await access(join(ROOT, ".guardianignore"), constants.F_OK);
      const source = await readFile(join(ROOT, "src/core/walk.ts"), "utf8");
      assert.match(source, /\.guardianignore/);
      assert.doesNotMatch(source, /\.rampartignore/);
    } finally {
      if (previous === undefined) delete process.env.GUARDIAN_UNIT_HOME;
      else process.env.GUARDIAN_UNIT_HOME = previous;
    }
  });

  test("CLI fixture stays offline, redacted, and repository-relative", async () => {
    const home = await mkdtemp("/tmp/guardian-unit-cli-");
    try {
      const { stdout } = await execFile(process.execPath, ["bin/guardian-unit.mjs", "scan", "examples/vulnerable-app", "--json"], {
        cwd: ROOT,
        env: { ...process.env, GUARDIAN_UNIT_HOME: home, GUARDIAN_UNIT_DOMAINS: "should-not-be-used.example" },
      });
      const result = JSON.parse(stdout) as import("../src/core/types.ts").ScanResult;
      const serialised = JSON.stringify(result);
      assert.ok(result.findings.length > 0);
      assert.ok(result.coverage.scannersRun.every((name) => name !== "surface"));
      assert.ok(result.coverage.limitations.some((line) => /Network checks were disabled/.test(line)));
      assert.ok(result.findings.every((f) => !f.location?.file.startsWith("/")));
      assert.ok(!serialised.includes("AKIAIOSFODNN7EXAMPLE"));
      assert.ok(!serialised.includes("hunter2"));

      const { stdout: help } = await execFile(process.execPath, ["bin/guardian-unit.mjs", "--help"], { cwd: ROOT });
      assert.doesNotMatch(help, /--(?:network|domain|skip surface)/);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });

  test("provider response bodies and triage secrets never reach stored or exported output", async () => {
    const bodySentinel = "PROVIDER_RESPONSE_BODY_SENTINEL";
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const originalFetch = globalThis.fetch;
    let providerWarning = "";
    globalThis.fetch = (async () => new Response(`${bodySentinel} ${secret}`, { status: 502 })) as typeof fetch;
    try {
      const provider = makeProvider({ kind: "custom", model: "test", baseUrl: "http://127.0.0.1:9" });
      await assert.rejects(provider.complete({ system: "s", user: "u" }), (err: Error) => {
        assert.equal(err.message, "Provider returned HTTP 502.");
        assert.ok(!err.message.includes(bodySentinel));
        assert.ok(!err.message.includes(secret));
        providerWarning = err.message;
        return true;
      });
    } finally {
      globalThis.fetch = originalFetch;
    }

    const dir = await mkdtemp("/tmp/guardian-unit-store-");
    const store = new Store(join(dir, "history.db"));
    try {
      store.setTriage("x", "/repo", "triaged", `keep private: ${secret}`);
      const triaged = store.applyTriage([mkFinding()], "/repo");
      const persisted = {
        scanId: "00000000-0000-4000-8000-000000000000",
        target: { ...triaged[0].target, id: `/tmp/${secret}`, label: secret },
        startedAt: "2026-01-01T00:00:00.000Z", finishedAt: "2026-01-01T00:00:01.000Z", durationMs: 1000,
        findings: [mkFinding({ title: secret, note: secret, location: { file: `src/${secret}.ts`, startLine: 1, endLine: 1 } })], warnings: [secret],
        coverage: { filesScanned: 1, filesSkipped: 0, skipReasons: {}, scannersRun: [], scannersSkipped: [], agentAnalysisRan: false, limitations: [] }, guardianUnitVersion: "0.1.0",
      };
      store.saveScan(persisted);
      const rawDb = (await readFile(join(dir, "history.db"))).toString("utf8");
      assert.ok(!rawDb.includes(secret));
      const json = safeJson({ ...triaged[0], warnings: [providerWarning] }, 2);
      const markdown = toMarkdown({
        scanId: "00000000-0000-4000-8000-000000000000",
        target: triaged[0].target,
        startedAt: "2026-01-01T00:00:00.000Z",
        finishedAt: "2026-01-01T00:00:01.000Z",
        durationMs: 1000,
        findings: triaged,
        warnings: [providerWarning],
        coverage: { filesScanned: 1, filesSkipped: 0, skipReasons: {}, scannersRun: [], scannersSkipped: [], agentAnalysisRan: false, limitations: [] },
        guardianUnitVersion: "0.1.0",
      });
      const sarif = toSarif({
        scanId: "00000000-0000-4000-8000-000000000000",
        target: triaged[0].target,
        startedAt: "2026-01-01T00:00:00.000Z",
        finishedAt: "2026-01-01T00:00:01.000Z",
        durationMs: 1000,
        findings: triaged,
        warnings: [providerWarning],
        coverage: { filesScanned: 1, filesSkipped: 0, skipReasons: {}, scannersRun: [], scannersSkipped: [], agentAnalysisRan: false, limitations: [] },
        guardianUnitVersion: "0.1.0",
      });
      for (const output of [json, markdown, sarif]) assert.ok(!output.includes(secret));
      assert.ok(!toTerminal(persisted, false).includes(secret));
      assert.ok(!sarif.includes(bodySentinel));
      assert.equal(JSON.parse(sarif).runs[0].tool.driver.name, "Guardian-Unit-Penetration-Testing Agent");
      assert.equal(PRODUCT, "Guardian-Unit-Penetration-Testing Agent");
    } finally {
      store.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("MCP final JSON-RPC and diagnostic boundaries redact forced secrets", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const rpc = serializeMcpMessage({ jsonrpc: "2.0", id: 1, error: { code: -32603, message: `raw ${secret}` } });
    const diagnostic = formatMcpDiagnostic(`raw ${secret}`);
    assert.ok(!rpc.includes(secret));
    assert.ok(!diagnostic.includes(secret));
    assert.doesNotThrow(() => JSON.parse(rpc));
  });

  test("MCP, CLI, and dashboard static scans redact output and never call fetch", async () => {
    const dir = await mkdtemp("/tmp/guardian-unit-public-");
    const log = join(dir, "fetch.log");
    const hook = join(dir, "fetch-hook.mjs");
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const secretTarget = await mkdtemp(`/tmp/${secret}-`);
    let server: ReturnType<typeof spawn> | undefined;
    await writeFile(hook, `import { appendFile } from 'node:fs/promises'; globalThis.fetch = async (url) => { await appendFile(process.env.GUARDIAN_FETCH_LOG, String(url) + '\\n'); throw new Error('outbound blocked') };`);
    const env = { ...process.env, GUARDIAN_UNIT_HOME: join(dir, "home"), GUARDIAN_FETCH_LOG: log, NODE_OPTIONS: `--import=${hook}` };
    try {
      const { stdout: cli } = await execFile(process.execPath, ["bin/guardian-unit.mjs", "scan", "examples/vulnerable-app", "--json"], { cwd: ROOT, env });
      assert.ok(!cli.includes("AKIAIOSFODNN7EXAMPLE") && !cli.includes("hunter2"));

      const mcp = await childOutput(["bin/guardian-unit.mjs", "mcp"], `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "security_scan", arguments: { path: join(ROOT, "examples/vulnerable-app") } } })}\n`, env);
      assert.equal(JSON.parse(mcp).id, 1);
      assert.ok(!mcp.includes("AKIAIOSFODNN7EXAMPLE") && !mcp.includes("hunter2"));

      const port = await freePort();
      server = spawn(process.execPath, ["bin/guardian-unit.mjs", "ui", ROOT, "--port", String(port), "--no-open"], { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
      let startup = "";
      await within(new Promise<void>((done, reject) => {
        server.stdout.on("data", (chunk) => { startup += chunk; if (startup.includes("token=")) done(); });
        server.once("error", reject);
        server.once("exit", (code) => reject(new Error(`dashboard exited during startup: ${code}`)));
      }), 5_000, "dashboard startup");
      const token = /token=([0-9a-f-]+)/.exec(startup)?.[1];
      assert.ok(token);
      const bad = await within(fetch(`http://127.0.0.1:${port}/api/browse?token=${token}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ path: `/tmp/${secret}` }) }), 5_000, "dashboard JSON request");
      const badText = await bad.text();
      assert.ok(!badText.includes(secret));
      const scan = await within(fetch(`http://127.0.0.1:${port}/api/scan?token=${token}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ path: secretTarget, network: true, domains: "ignored.example" }) }), 5_000, "dashboard SSE request");
      const sse = await within(scan.text(), 5_000, "dashboard SSE response");
      assert.ok(!sse.includes(secret) && !sse.includes("hunter2"));
      const scanId = /"scanId":"([0-9a-f-]{36})"/.exec(sse)?.[1];
      assert.ok(scanId);
      const report = await within(fetch(`http://127.0.0.1:${port}/api/report/${scanId}.json?token=${token}`), 5_000, "dashboard report request");
      assert.ok(!(await report.text()).includes(secret));
      const fetchLog = await readFile(log, "utf8").catch(() => "");
      assert.equal(fetchLog, "", `static entry point made outbound requests: ${fetchLog}`);
    } finally {
      if (server && !server.killed) {
        const closed = new Promise<void>((done) => server!.once("close", () => done()));
        server.kill("SIGTERM");
        const graceful = await within(closed, 2_000, "dashboard shutdown").then(() => true).catch(() => false);
        if (!graceful) {
          server.kill("SIGKILL");
          await within(closed, 2_000, "forced dashboard shutdown");
        }
      }
      await rm(secretTarget, { recursive: true, force: true });
      await rm(dir, { recursive: true, force: true });
    }
  });
});
