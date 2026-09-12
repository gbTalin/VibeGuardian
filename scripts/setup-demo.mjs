#!/usr/bin/env node
import { readFile, writeFile, mkdir, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PRODUCT_ID = "guardian-unit-penetration-testing-agent";
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function usage() {
  return `Guardian-Unit demo setup

Usage:
  node scripts/setup-demo.mjs [project] \\
    --target https://app.example.com \\
    --environment production \\
    --owner security@example.com

This creates an expiring target approval, a Codex project pointer, and the
minimal GitHub workflow. Existing conflicting files are never overwritten.`;
}

function parseArgs(argv) {
  const flags = {};
  const positionals = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }
    const equals = token.indexOf("=");
    if (equals !== -1) {
      flags[token.slice(2, equals)] = token.slice(equals + 1);
      continue;
    }
    const key = token.slice(2);
    if (key === "help") {
      flags.help = true;
      continue;
    }
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for --${key}`);
    flags[key] = value;
    i += 1;
  }
  if (positionals.length > 1) throw new Error("Pass at most one project directory.");
  return { project: resolve(positionals[0] ?? process.cwd()), flags };
}

function validateText(label, value) {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`--${label} is required.`);
  if (/\p{Cc}/u.test(value)) throw new Error(`--${label} cannot contain control characters.`);
  return value.trim();
}

function validateTarget(value, environment) {
  let target;
  try {
    target = new URL(value);
  } catch {
    throw new Error("--target must be an exact http(s) origin.");
  }
  if (
    !["http:", "https:"].includes(target.protocol) ||
    target.username ||
    target.password ||
    target.pathname !== "/" ||
    target.search ||
    target.hash ||
    target.origin !== value
  ) {
    throw new Error("--target must be an exact origin, for example https://app.example.com (no trailing slash or path).");
  }
  if (environment !== "local" && target.protocol !== "https:") {
    throw new Error("Staging and production targets must use HTTPS.");
  }
  if (environment === "local" && !["localhost", "127.0.0.1", "[::1]"].includes(target.hostname)) {
    throw new Error("Local approvals are limited to localhost, 127.0.0.1, or ::1.");
  }
  return target.origin;
}

async function putIfSafe(destination, content, label, summary) {
  try {
    const existing = await readFile(destination, "utf8");
    if (existing === content) {
      summary.unchanged.push(label);
    } else {
      summary.conflicts.push(`${label}: ${destination}`);
    }
    return;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }

  await mkdir(dirname(destination), { recursive: true });
  try {
    await writeFile(destination, content, { encoding: "utf8", flag: "wx" });
    summary.created.push(label);
  } catch (error) {
    if (error?.code === "EEXIST") summary.conflicts.push(`${label}: ${destination}`);
    else throw error;
  }
}

async function putAuthorization(project, record, summary) {
  const destination = resolve(project, ".guardian-unit/targets.json");
  try {
    const existingText = await readFile(destination, "utf8");
    const existing = JSON.parse(existingText);
    const match = existing?.schemaVersion === 1 && existing.targets?.some(
      (item) => item?.origin === record.origin && item?.environment === record.environment && item?.owner === record.owner,
    );
    if (match) summary.unchanged.push("authorized target");
    else summary.conflicts.push(`authorized target: ${destination}`);
    return;
  } catch (error) {
    if (error?.code !== "ENOENT") {
      summary.conflicts.push(`authorized target: ${destination}`);
      return;
    }
  }

  await mkdir(dirname(destination), { recursive: true });
  try {
    await writeFile(
      destination,
      `${JSON.stringify({ schemaVersion: 1, targets: [record] }, null, 2)}\n`,
      { encoding: "utf8", flag: "wx" },
    );
    summary.created.push("authorized target");
  } catch (error) {
    if (error?.code === "EEXIST") summary.conflicts.push(`authorized target: ${destination}`);
    else throw error;
  }
}

async function main() {
  let parsed;
  try {
    parsed = parseArgs(process.argv.slice(2));
    if (parsed.flags.help) {
      console.log(usage());
      return;
    }
    const projectInfo = await stat(parsed.project).catch(() => null);
    if (!projectInfo?.isDirectory()) throw new Error(`Project directory does not exist: ${parsed.project}`);
    const environment = validateText("environment", parsed.flags.environment);
    if (!["local", "staging", "production"].includes(environment)) {
      throw new Error("--environment must be local, staging, or production.");
    }
    const owner = validateText("owner", parsed.flags.owner);
    const origin = validateTarget(validateText("target", parsed.flags.target), environment);
    const now = new Date();
    const record = {
      origin,
      environment,
      owner,
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString(),
      requestBudget: 4,
      maxRedirects: 1,
      timeoutMs: 3000,
      ratePerSecond: 1,
      corsPreflight: false,
      approvedPaths: [],
    };

    const summary = { created: [], unchanged: [], conflicts: [] };
    await putAuthorization(parsed.project, record, summary);

    const pluginRoot = resolve(PACKAGE_ROOT, "plugins", PRODUCT_ID);
    const pointer = {
      schemaVersion: 1,
      managedBy: PRODUCT_ID,
      pluginRoot,
      launcher: resolve(PACKAGE_ROOT, "bin/guardian-unit.mjs"),
      mcp: {
        command: process.execPath,
        args: [resolve(PACKAGE_ROOT, "bin/guardian-unit.mjs"), "mcp"],
        env: { GUARDIAN_UNIT_REPO_ROOT: parsed.project },
      },
    };
    await putIfSafe(
      resolve(parsed.project, ".codex/guardian-unit.json"),
      `${JSON.stringify(pointer, null, 2)}\n`,
      "Codex plugin pointer",
      summary,
    );

    const workflowSource = resolve(PACKAGE_ROOT, ".github/workflows/guardian-unit-gate.yml");
    const workflow = await readFile(workflowSource, "utf8");
    await putIfSafe(
      resolve(parsed.project, ".github/workflows/guardian-unit-gate.yml"),
      workflow,
      "GitHub release gate",
      summary,
    );

    console.log(`\nGuardian-Unit demo setup: ${parsed.project}`);
    for (const item of summary.created) console.log(`  CREATED    ${item}`);
    for (const item of summary.unchanged) console.log(`  UNCHANGED  ${item}`);
    for (const item of summary.conflicts) console.log(`  CONFLICT   ${item}`);
    console.log(`\nCodex plugin: ${pluginRoot}`);
    console.log("New target approvals last 24 hours. Re-run with a reviewed record before probing again.");
    console.log(`Run the core demo: ${process.execPath} ${JSON.stringify(resolve(PACKAGE_ROOT, "scripts/run-demo.mjs"))}\n`);

    if (summary.conflicts.length > 0) {
      console.error("Nothing conflicting was overwritten. Review the paths above and merge them manually.");
      process.exitCode = 2;
    }
  } catch (error) {
    console.error(`Guardian-Unit setup stopped: ${error instanceof Error ? error.message : String(error)}\n`);
    console.error(usage());
    process.exitCode = 1;
  }
}

await main();
