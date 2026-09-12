import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { stdout } from "node:process";
import { buildEngine, ALL_SCANNERS } from "./scanners/index.ts";
import { loadConfig, saveConfig, privacyPosture, type GuardianUnitConfig } from "./core/config.ts";
import { Store } from "./core/store.ts";
import { toMarkdown, toTerminal } from "./report/markdown.ts";
import { toSarif } from "./report/sarif.ts";
import { loadAgents } from "./agents/loader.ts";
import { makeProvider, tierOf } from "./agents/providers.ts";
import { reviewFindings } from "./agents/runtime.ts";
import { countBySeverity, rank } from "./core/finding.ts";
import { PRODUCT, TAGLINE, VERSION } from "./version.ts";
import type { Severity } from "./core/types.ts";

const useColor = stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string, s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);

interface Args {
  _: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const out: Args = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [k, inline] = a.slice(2).split("=");
      if (inline !== undefined) out.flags[k] = inline;
      else if (argv[i + 1] && !argv[i + 1].startsWith("-")) out.flags[k] = argv[++i];
      else out.flags[k] = true;
    } else if (a.startsWith("-") && a.length > 1) {
      out.flags[a.slice(1)] = true;
    } else {
      out._.push(a);
    }
  }
  return out;
}

function banner(): string {
  return [
    "",
    `  ${c("1;36", PRODUCT)} ${c("90", `v${VERSION}`)}`,
    `  ${c("90", TAGLINE)}`,
    "",
  ].join("\n");
}

function help(): string {
  return [
    banner(),
    `  ${c("1", "Usage")}`,
    "",
    `    guardian-unit                      Open the dashboard in your browser`,
    `    guardian-unit scan [path]          Scan a folder and print the results`,
    `    guardian-unit ui [path]            Open the dashboard for a specific folder`,
    `    guardian-unit setup                Choose a model for the agent review layer`,
    `    guardian-unit doctor               Check that everything is working`,
    `    guardian-unit agents               List the security agents available`,
    `    guardian-unit rules                List every check Guardian Unit can run`,
    `    guardian-unit mcp                  Run as an MCP server for AI coding tools`,
    "",
    `  ${c("1", "Scan options")}`,
    "",
    `    --agents                     Also run agent review over the findings`,
    `    --only secrets,code          Run only these checks`,
    `    --skip surface               Skip these checks`,
    `    --sarif out.sarif            Write SARIF for code-scanning platforms`,
    `    --markdown report.md         Write a full human-readable report`,
    `    --json                       Print raw JSON to stdout`,
    `    --ci                         Exit non-zero if anything at --fail-on or worse`,
    `    --fail-on high               critical | high | medium | low | never`,
    "",
    `  ${c("1", "Privacy")}`,
    "",
    `    Guardian Unit runs entirely on this machine with no telemetry and no`,
    `    network access in its static scanner.`,
    "",
  ].join("\n");
}

async function cmdScan(args: Args): Promise<number> {
  const target = resolve(args._[1] ?? process.cwd());
  const cfg = await loadConfig();

  // This core is intentionally static and offline. Authorized live probing is
  // provided separately so an inherited broad network scanner cannot be
  // reached through the default product command.
  const runtimeCfg: GuardianUnitConfig = { ...cfg, allowNetwork: false };

  const engine = buildEngine();
  const only = typeof args.flags.only === "string" ? args.flags.only.split(",").map((s) => s.trim()) : undefined;
  const skip = typeof args.flags.skip === "string" ? args.flags.skip.split(",").map((s) => s.trim()) : undefined;

  const quiet = Boolean(args.flags.json);
  if (!quiet) {
    process.stderr.write(banner());
    process.stderr.write(`  ${c("90", `Scanning ${target}`)}\n`);
    process.stderr.write("\n");
  }

  let lastLine = "";
  const controller = new AbortController();
  process.on("SIGINT", () => controller.abort());

  const result = await engine.scan(target, {
    config: runtimeCfg,
    only,
    skip,
    signal: controller.signal,
    onProgress: (msg, frac) => {
      if (quiet || !stdout.isTTY) return;
      const pct = frac === undefined ? "" : ` ${Math.round(frac * 100)}%`;
      const line = `  ${c("36", "»")} ${msg}${pct}`;
      if (line !== lastLine) {
        process.stderr.write(`\r${" ".repeat(Math.max(lastLine.length, 0))}\r${line}`);
        lastLine = line;
      }
    },
  });
  if (lastLine && stdout.isTTY && !quiet) process.stderr.write(`\r${" ".repeat(lastLine.length)}\r`);

  // Optional agent review pass.
  if (args.flags.agents) {
    const provider = makeProvider(cfg.provider);
    const status = await provider.available();
    if (!status.ok) {
      result.warnings.push(`Agent review was requested but could not run: ${status.detail}`);
      if (!quiet) process.stderr.write(`  ${c("33", `Agent review skipped: ${status.detail}`)}\n`);
    } else {
      const agents = await loadAgents(cfg.agentsDir);
      if (agents.length === 0) {
        result.warnings.push("Agent review was requested but no agent definitions were found.");
      } else {
        if (!quiet) process.stderr.write(`  ${c("36", `${agents.length} agents loaded. Reviewing findings with ${provider.model}...`)}\n`);
        const { findings, outcome } = await reviewFindings(result.findings, {
          provider,
          agents,
          root: target,
          minSeverity: "high",
          signal: controller.signal,
        });
        result.findings = rank(findings);
        result.coverage.agentAnalysisRan = outcome.reviewed > 0;
        result.warnings.push(...outcome.warnings);
        if (outcome.tamperingDetected.length > 0) {
          result.warnings.push(
            `${outcome.tamperingDetected.length} reviewed file(s) contained text that appears aimed at manipulating an automated reviewer. Those findings were kept at full severity and need manual inspection.`,
          );
        }
        if (!quiet) {
          process.stderr.write(
            `  ${c("90", `Reviewed ${outcome.reviewed}, skipped ${outcome.skipped}, failed ${outcome.failed}.`)}\n`,
          );
        }
      }
    }
  }

  // Persist and diff.
  let store: Store | null = null;
  try {
    store = new Store();
    result.findings = store.applyTriage(result.findings, result.target.id);
    const diff = store.diffAgainstPrevious(result);
    store.saveScan(result);
    if (!quiet && diff.previousScanId) {
      process.stderr.write(
        `  ${c("90", `Since the last scan: ${diff.resolved.length} resolved, ${diff.introduced.length} new, ${diff.persisting.length} still open.`)}\n`,
      );
    }
  } catch (err) {
    result.warnings.push(`Could not save scan history: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    store?.close();
  }

  // Output.
  if (args.flags.json) {
    stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    stdout.write(toTerminal(result, useColor));
  }
  if (typeof args.flags.sarif === "string") {
    await writeFile(args.flags.sarif, toSarif(result));
    if (!quiet) process.stderr.write(`  ${c("90", `SARIF written to ${args.flags.sarif}`)}\n\n`);
  }
  if (typeof args.flags.markdown === "string") {
    await writeFile(args.flags.markdown, toMarkdown(result));
    if (!quiet) process.stderr.write(`  ${c("90", `Report written to ${args.flags.markdown}`)}\n\n`);
  }

  if (!args.flags.ci) {
    if (!quiet) {
      process.stderr.write(`  ${c("90", "Run")} ${c("1", "guardian-unit ui")} ${c("90", "to explore these findings in your browser.")}\n\n`);
    }
    return 0;
  }

  const failOn = (typeof args.flags["fail-on"] === "string" ? args.flags["fail-on"] : cfg.failOn) as
    | Severity
    | "never";
  if (failOn === "never") return 0;
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const threshold = order.indexOf(failOn);
  const counts = countBySeverity(result.findings.filter((f) => f.status === "open"));
  const breached = order.slice(0, threshold + 1).some((s) => counts[s] > 0);
  if (breached) {
    process.stderr.write(`  ${c("1;31", `Failing: findings at or above ${failOn}.`)}\n\n`);
    return 1;
  }
  return 0;
}

async function cmdAgents(): Promise<number> {
  const cfg = await loadConfig();
  const agents = await loadAgents(cfg.agentsDir);
  process.stdout.write(banner());
  if (agents.length === 0) {
    process.stdout.write(
      `  ${c("33", "No agent definitions found.")}\n\n` +
        `  Guardian Unit looks for markdown agent files in:\n` +
        `    ~/.guardian-unit/agents\n` +
        `    the security/ directory of an agency-agents checkout\n\n` +
        `  Set GUARDIAN_UNIT_AGENTS_DIR to point somewhere else.\n\n`,
    );
    return 0;
  }
  process.stdout.write(`  ${c("1", `${agents.length} security agents available`)}\n\n`);
  for (const a of agents) {
    process.stdout.write(`  ${a.emoji ?? "•"}  ${c("1", a.name)}\n`);
    process.stdout.write(`      ${c("90", a.description.slice(0, 110))}\n\n`);
  }
  process.stdout.write(`  ${c("90", "Run a scan with --agents to have these review your findings.")}\n\n`);
  return 0;
}

async function cmdRules(args: Args): Promise<number> {
  const engine = buildEngine();
  if (args.flags.json) {
    stdout.write(
      `${JSON.stringify(
        engine.list().map((s) => ({ scanner: s.name, title: s.title, rules: s.rules })),
        null,
        2,
      )}\n`,
    );
    return 0;
  }
  process.stdout.write(banner());
  process.stdout.write(`  ${c("1", `${engine.ruleCount()} checks across ${engine.list().length} scanners`)}\n\n`);
  for (const s of engine.list()) {
    process.stdout.write(`  ${c("1;36", s.title)} ${c("90", `(${s.name})`)}\n`);
    process.stdout.write(`  ${c("90", s.description)}\n\n`);
    for (const r of s.rules) {
      const sev = r.severity.toUpperCase().padEnd(8);
      process.stdout.write(`     ${c(r.severity === "critical" ? "1;31" : r.severity === "high" ? "31" : "90", sev)} ${r.id}\n`);
      process.stdout.write(`              ${c("90", r.title)}\n`);
    }
    process.stdout.write("\n");
  }
  return 0;
}

async function cmdDoctor(): Promise<number> {
  const cfg = await loadConfig();
  process.stdout.write(banner());
  const ok = (s: string) => `  ${c("32", "ok")}   ${s}\n`;
  const warn = (s: string) => `  ${c("33", "note")} ${s}\n`;

  process.stdout.write(ok(`Node ${process.versions.node}`));
  try {
    await import("node:sqlite");
    process.stdout.write(ok("Scan history storage available (node:sqlite)"));
  } catch {
    process.stdout.write(warn("node:sqlite unavailable — scans will run but history will not be saved"));
  }

  const engine = buildEngine();
  process.stdout.write(ok(`${engine.list().length} scanners, ${engine.ruleCount()} checks loaded`));

  const agents = await loadAgents(cfg.agentsDir);
  process.stdout.write(
    agents.length > 0
      ? ok(`${agents.length} security agents found`)
      : warn("No agent definitions found — deterministic scanning still works fully"),
  );

  const provider = makeProvider(cfg.provider);
  const status = await provider.available();
  process.stdout.write(status.ok ? ok(status.detail) : warn(status.detail));

  process.stdout.write(`\n  ${c("1", "Privacy posture")}\n  ${c("90", privacyPosture(cfg))}\n\n`);
  return 0;
}

async function cmdSetup(args: Args): Promise<number> {
  const cfg = await loadConfig();
  const kind = args._[1] as GuardianUnitConfig["provider"]["kind"] | undefined;

  if (!kind) {
    process.stdout.write(banner());
    process.stdout.write(
      [
        `  ${c("1", "Guardian Unit works fully without a model.")} The agent review layer is optional.`,
        "",
        `  ${c("1", "To stay completely offline")} — recommended, and required if your code cannot leave the network:`,
        "",
        `    ${c("36", "guardian-unit setup ollama --model qwen2.5-coder:14b")}`,
        "",
        `    Install Ollama from https://ollama.com, then: ollama pull qwen2.5-coder:14b`,
        `    Your code never leaves this machine.`,
        "",
        `  ${c("1", "To use your own hosted account")} — stronger reasoning, but selected code`,
        `  excerpts are sent to that provider:`,
        "",
        `    ${c("36", "guardian-unit setup anthropic --model claude-sonnet-5")}   (reads ANTHROPIC_API_KEY)`,
        `    ${c("36", "guardian-unit setup openai --model gpt-5")}                (reads OPENAI_API_KEY)`,
        "",
        `  ${c("1", "To turn it off:")}`,
        "",
        `    ${c("36", "guardian-unit setup none")}`,
        "",
        `  ${c("90", "Guardian Unit never stores an API key. It reads them from the environment at call time.")}`,
        "",
        `  Current: ${c("90", privacyPosture(cfg))}`,
        "",
      ].join("\n"),
    );
    return 0;
  }

  const model = typeof args.flags.model === "string" ? args.flags.model : undefined;
  const baseUrl = typeof args.flags["base-url"] === "string" ? args.flags["base-url"] : undefined;
  const next: GuardianUnitConfig = {
    ...cfg,
    provider: {
      kind,
      model: model ?? (kind === "ollama" ? "qwen2.5-coder:14b" : undefined),
      baseUrl: baseUrl ?? (kind === "ollama" ? "http://localhost:11434" : undefined),
    },
  };
  next.provider.tier = tierOf(next.provider);
  await saveConfig(next);

  const provider = makeProvider(next.provider);
  const status = await provider.available();
  process.stdout.write(banner());
  process.stdout.write(`  ${status.ok ? c("32", "Configured.") : c("33", "Saved, but not usable yet.")}\n`);
  process.stdout.write(`  ${c("90", status.detail)}\n\n`);
  process.stdout.write(`  ${c("90", privacyPosture(next))}\n\n`);
  return 0;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0] ?? (process.stdout.isTTY ? "ui" : "help");

  if (args.flags.version || args.flags.v) {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  if (args.flags.help || args.flags.h || cmd === "help") {
    process.stdout.write(help());
    return;
  }

  let code = 0;
  switch (cmd) {
    case "scan":
      code = await cmdScan(args);
      break;
    case "ui":
    case "serve":
    case "dashboard": {
      const { startServer } = await import("./server/server.ts");
      await startServer({
        root: resolve(args._[1] ?? process.cwd()),
        port: Number(args.flags.port ?? 7331),
        open: !args.flags["no-open"],
      });
      return; // server keeps the process alive
    }
    case "mcp": {
      const { startMcpServer } = await import("./server/mcp.ts");
      await startMcpServer();
      return;
    }
    case "agents":
      code = await cmdAgents();
      break;
    case "rules":
      code = await cmdRules(args);
      break;
    case "doctor":
      code = await cmdDoctor();
      break;
    case "setup":
      code = await cmdSetup(args);
      break;
    default:
      process.stderr.write(`Unknown command: ${cmd}\n`);
      process.stdout.write(help());
      code = 1;
  }
  // Set the code rather than calling process.exit(): exit() discards anything
  // still buffered in a piped stdout, which silently truncates --json output.
  process.exitCode = code;
}

main().catch((err) => {
  process.stderr.write(`\n  ${c("1;31", "Guardian Unit hit an error:")} ${err instanceof Error ? err.message : String(err)}\n\n`);
  if (process.env.GUARDIAN_UNIT_DEBUG) console.error(err);
  process.exitCode = 2;
});
