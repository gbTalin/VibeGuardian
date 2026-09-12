import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile, readdir, stat } from "node:fs/promises";
import { join, dirname, resolve, sep } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { buildEngine } from "../scanners/index.ts";
import { loadConfig, saveConfig, privacyPosture, type GuardianUnitConfig } from "../core/config.ts";
import { Store } from "../core/store.ts";
import { toMarkdown } from "../report/markdown.ts";
import { toSarif } from "../report/sarif.ts";
import { loadAgents } from "../agents/loader.ts";
import { makeProvider, tierOf } from "../agents/providers.ts";
import { reviewFindings } from "../agents/runtime.ts";
import { rank } from "../core/finding.ts";
import { redact, safeJson } from "../core/redact.ts";
import { PRODUCT, VERSION } from "../version.ts";
import type { FindingStatus, ScanResult } from "../core/types.ts";

/**
 * The local dashboard.
 *
 * Binds to loopback only and requires a token that is printed to the terminal
 * and embedded in the URL Guardian-Unit-Penetration-Testing Agent opens. Both matter: a security tool that
 * exposes an unauthenticated "scan any path on this machine and show me the
 * results" endpoint on 0.0.0.0 would be a serious vulnerability in its own
 * right, and every other program on the machine can reach 127.0.0.1.
 */

const UI_DIR = join(dirname(fileURLToPath(import.meta.url)), "ui");

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
};

interface ServerOptions {
  root: string;
  port: number;
  open: boolean;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = safeJson(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
  });
  res.end(payload);
}

function reportFilename(label: string, format: string): string {
  const normalized = redact(label)
    .normalize("NFKD")
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return `guardian-unit-${normalized || "scan"}.${format}`;
}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 1_000_000) throw new Error("request body too large");
    chunks.push(chunk as Buffer);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function constantTimeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

export async function startServer(opts: ServerOptions): Promise<void> {
  const token = randomUUID();
  const engine = buildEngine();
  let store: Store | null = null;
  try {
    store = new Store();
  } catch {
    /* history is optional */
  }

  /** In-flight and completed scans, kept in memory for this session. */
  const scans = new Map<string, ScanResult>();
  const running = new Map<string, AbortController>();

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const path = url.pathname;

    // Defence against DNS rebinding: a malicious page can point a hostname it
    // controls at 127.0.0.1, but it cannot forge the Host header.
    const host = (req.headers.host ?? "").split(":")[0];
    if (host && !["localhost", "127.0.0.1", "[::1]", "::1"].includes(host)) {
      res.writeHead(403).end("Guardian-Unit-Penetration-Testing Agent only accepts requests addressed to localhost.");
      return;
    }
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'none'; base-uri 'none'",
    );

    // Static assets and the shell are unauthenticated; every API route is not.
    if (path.startsWith("/api/")) {
      const supplied = url.searchParams.get("token") ?? (req.headers["x-guardian-unit-token"] as string) ?? "";
      if (!constantTimeEqual(supplied, token)) {
        json(res, 401, { error: "Invalid or missing token. Reopen the URL Guardian-Unit-Penetration-Testing Agent printed in your terminal." });
        return;
      }
    }

    try {
      // ---- static ---------------------------------------------------------
      if (req.method === "GET" && !path.startsWith("/api/")) {
        const name = path === "/" ? "index.html" : path.replace(/^\/+/, "");
        if (name.includes("..") || name.includes("\0")) {
          res.writeHead(400).end();
          return;
        }
        try {
          const file = join(UI_DIR, name);
          if (!file.startsWith(UI_DIR)) {
            res.writeHead(400).end();
            return;
          }
          const body = await readFile(file);
          const ext = name.slice(name.lastIndexOf("."));
          res.writeHead(200, {
            "content-type": MIME[ext] ?? "application/octet-stream",
            "cache-control": "no-store",
          });
          res.end(body);
        } catch {
          res.writeHead(404, { "content-type": "text/plain" }).end("Not found");
        }
        return;
      }

      // ---- status ---------------------------------------------------------
      if (path === "/api/status" && req.method === "GET") {
        const cfg = await loadConfig();
        const provider = makeProvider(cfg.provider);
        const [providerStatus, agents] = await Promise.all([
          provider.available(),
          loadAgents(cfg.agentsDir),
        ]);
        json(res, 200, {
          product: PRODUCT,
          version: VERSION,
          defaultRoot: opts.root,
          home: homedir(),
          privacy: privacyPosture(cfg),
          allowNetwork: false,
          provider: {
            kind: cfg.provider.kind,
            model: cfg.provider.model ?? null,
            describe: provider.describe(),
            ok: providerStatus.ok,
            detail: providerStatus.detail,
            tier: tierOf(cfg.provider),
          },
          agents: agents.map((a) => ({
            slug: a.slug,
            name: a.name,
            description: a.description,
            emoji: a.emoji,
            color: a.color,
          })),
          scanners: engine.list().map((s) => ({
            name: s.name,
            title: s.title,
            description: s.description,
            requiresNetwork: Boolean(s.requiresNetwork),
            ruleCount: s.rules.length,
          })),
          ruleCount: engine.ruleCount(),
          history: store?.recentScans(20) ?? [],
        });
        return;
      }

      // ---- rule catalogue -------------------------------------------------
      if (path === "/api/rules" && req.method === "GET") {
        json(res, 200, {
          scanners: engine.list().map((s) => ({
            name: s.name,
            title: s.title,
            description: s.description,
            rules: s.rules,
          })),
        });
        return;
      }

      // ---- directory browsing ---------------------------------------------
      if (path === "/api/browse" && req.method === "POST") {
        const body = await readBody(req);
        const dir = resolve(String(body.path ?? homedir()));
        try {
          const entries = await readdir(dir, { withFileTypes: true });
          const dirs = entries
            .filter((e) => e.isDirectory() && !e.name.startsWith("."))
            .map((e) => ({ name: e.name, path: join(dir, e.name) }))
            .sort((a, b) => a.name.localeCompare(b.name))
            .slice(0, 400);
          const parent = dirname(dir);
          json(res, 200, {
            path: dir,
            parent: parent === dir ? null : parent,
            crumbs: dir.split(sep).filter(Boolean),
            dirs,
          });
        } catch (err) {
          json(res, 400, { error: `Cannot read ${dir}: ${err instanceof Error ? err.message : String(err)}` });
        }
        return;
      }

      // ---- scan (server-sent events) --------------------------------------
      if (path === "/api/scan" && req.method === "POST") {
        const body = await readBody(req);
        const target = resolve(String(body.path ?? opts.root));
        try {
          const st = await stat(target);
          if (!st.isDirectory()) throw new Error("not a directory");
        } catch {
          json(res, 400, { error: `${target} is not a folder Guardian-Unit-Penetration-Testing Agent can read.` });
          return;
        }

        const cfg = await loadConfig();
        const withAgents = body.agents === true;
        const runtimeCfg: GuardianUnitConfig = {
          ...cfg,
          // Static scans are offline. The separately authorized probe is the
          // only future route that may make bounded live requests.
          allowNetwork: false,
        };

        res.writeHead(200, {
          "content-type": "text/event-stream; charset=utf-8",
          "cache-control": "no-cache",
          connection: "keep-alive",
          "x-accel-buffering": "no",
        });
        const send = (event: string, data: unknown) => {
          res.write(`event: ${event}\ndata: ${safeJson(data)}\n\n`);
        };

        const controller = new AbortController();
        const runId = randomUUID();
        running.set(runId, controller);
        req.on("close", () => controller.abort());
        send("started", { runId, target });

        try {
          const result = await engine.scan(target, {
            config: runtimeCfg,
            signal: controller.signal,
            onProgress: (message, fraction) => send("progress", { message, fraction }),
          });

          if (withAgents) {
            const provider = makeProvider(cfg.provider);
            const status = await provider.available();
            if (!status.ok) {
              result.warnings.push(`Agent review could not run: ${status.detail}`);
              send("progress", { message: `Agent review skipped: ${status.detail}` });
            } else {
              const agents = await loadAgents(cfg.agentsDir);
              send("progress", { message: `Reviewing findings with ${agents.length} agents`, fraction: 0.9 });
              const { findings, outcome } = await reviewFindings(result.findings, {
                provider,
                agents,
                root: target,
                minSeverity: "high",
                signal: controller.signal,
                onProgress: (m, f) => send("progress", { message: m, fraction: 0.9 + (f ?? 0) * 0.1 }),
              });
              result.findings = rank(findings);
              result.coverage.agentAnalysisRan = outcome.reviewed > 0;
              result.warnings.push(...outcome.warnings);
              if (outcome.tamperingDetected.length > 0) {
                result.warnings.push(
                  `${outcome.tamperingDetected.length} reviewed file(s) contain text that appears aimed at manipulating an automated reviewer. Those findings were kept at full severity and need a human look.`,
                );
              }
            }
          }

          let diff = null;
          if (store) {
            result.findings = store.applyTriage(result.findings, result.target.id);
            diff = store.diffAgainstPrevious(result);
            store.saveScan(result);
          }
          scans.set(result.scanId, result);
          send("done", {
            result,
            diff: diff
              ? {
                  previousScanId: diff.previousScanId,
                  resolved: diff.resolved.length,
                  introduced: diff.introduced.length,
                  persisting: diff.persisting.length,
                  introducedIds: diff.introduced.map((f) => f.id),
                }
              : null,
          });
        } catch (err) {
          send("error", { message: redact(err instanceof Error ? err.message : String(err)) });
        } finally {
          running.delete(runId);
          res.end();
        }
        return;
      }

      // ---- triage ----------------------------------------------------------
      if (path === "/api/triage" && req.method === "POST") {
        const body = await readBody(req);
        const findingId = String(body.findingId ?? "");
        const targetId = String(body.targetId ?? "");
        const status = String(body.status ?? "open") as FindingStatus;
        const note = body.note ? redact(String(body.note).slice(0, 2000)) : undefined;
        const valid: FindingStatus[] = ["open", "triaged", "fixed", "suppressed", "false-positive"];
        if (!findingId || !targetId || !valid.includes(status)) {
          json(res, 400, { error: "findingId, targetId and a valid status are required." });
          return;
        }
        store?.setTriage(findingId, targetId, status, note);
        for (const result of scans.values()) {
          const f = result.findings.find((x) => x.id === findingId);
          if (f) {
            f.status = status;
            f.note = note;
          }
        }
        json(res, 200, { ok: true });
        return;
      }

      // ---- reports ---------------------------------------------------------
      const reportMatch = /^\/api\/report\/([0-9a-f-]{36})\.(md|sarif|json)$/.exec(path);
      if (reportMatch && req.method === "GET") {
        const [, id, format] = reportMatch;
        const result = scans.get(id);
        if (!result) {
          json(res, 404, { error: "That scan is not in this session's memory. Re-run the scan." });
          return;
        }
        const bodies: Record<string, [string, string]> = {
          md: [toMarkdown(result), "text/markdown; charset=utf-8"],
          sarif: [toSarif(result), "application/json; charset=utf-8"],
          json: [safeJson(result, 2), "application/json; charset=utf-8"],
        };
        const [content, type] = bodies[format];
        res.writeHead(200, {
          "content-type": type,
          "content-disposition": `attachment; filename="${reportFilename(result.target.label, format)}"`,
        });
        res.end(content);
        return;
      }

      // ---- provider settings ------------------------------------------------
      if (path === "/api/provider" && req.method === "POST") {
        const body = await readBody(req);
        const cfg = await loadConfig();
        const kind = String(body.kind ?? "none") as GuardianUnitConfig["provider"]["kind"];
        const next: GuardianUnitConfig = {
          ...cfg,
          provider: {
            kind,
            model: body.model ? String(body.model) : kind === "ollama" ? "qwen2.5-coder:14b" : undefined,
            baseUrl: body.baseUrl
              ? String(body.baseUrl)
              : kind === "ollama"
                ? "http://localhost:11434"
                : undefined,
          },
        };
        next.provider.tier = tierOf(next.provider);
        await saveConfig(next);
        const provider = makeProvider(next.provider);
        const status = await provider.available();
        json(res, 200, {
          ok: status.ok,
          detail: status.detail,
          describe: provider.describe(),
          privacy: privacyPosture(next),
        });
        return;
      }

      json(res, 404, { error: "No such endpoint." });
    } catch (err) {
      json(res, 500, { error: err instanceof Error ? err.message : String(err) });
    }
  });

  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    // Loopback only. Never 0.0.0.0.
    server.listen(opts.port, "127.0.0.1", resolveListen);
  });

  const address = `http://localhost:${opts.port}/?token=${token}`;
  const bold = (s: string) => (process.stdout.isTTY ? `\x1b[1m${s}\x1b[0m` : s);
  const dim = (s: string) => (process.stdout.isTTY ? `\x1b[90m${s}\x1b[0m` : s);

  process.stdout.write(
    [
      "",
      `  ${bold(PRODUCT)} ${dim(`v${VERSION}`)} is running.`,
      "",
      `  ${bold(address)}`,
      "",
      dim("  Bound to localhost only. The token in that URL is required for every"),
      dim("  action, so nothing else on this machine can drive it."),
      "",
      dim("  Press Ctrl+C to stop."),
      "",
    ].join("\n"),
  );

  if (opts.open) {
    const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
    try {
      spawn(cmd, [address], { stdio: "ignore", detached: true, shell: process.platform === "win32" }).unref();
    } catch {
      /* the URL is printed above; opening is a convenience */
    }
  }

  const shutdown = () => {
    for (const controller of running.values()) controller.abort();
    store?.close();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1500).unref();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
