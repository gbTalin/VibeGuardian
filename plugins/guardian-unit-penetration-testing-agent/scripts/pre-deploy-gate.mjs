#!/usr/bin/env node

import { access } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const MAX_INPUT_BYTES = 1024 * 1024;
const GATE_TIMEOUT_MS = 90_000;
const DEPLOY_COMMANDS = [
  /(?:^|[;&|\n]\s*)vercel\s+deploy(?:\s|$)/i,
  /(?:^|[;&|\n]\s*)netlify\s+deploy(?:\s|$)/i,
  /(?:^|[;&|\n]\s*)fly\s+deploy(?:\s|$)/i,
  /(?:^|[;&|\n]\s*)wrangler\s+deploy(?:\s|$)/i,
  /(?:^|[;&|\n]\s*)firebase\s+deploy(?:\s|$)/i,
  /(?:^|[;&|\n]\s*)npm\s+run\s+deploy(?:\s|$)/i,
  /(?:^|[;&|\n]\s*)pnpm\s+run\s+deploy(?:\s|$)/i,
  /(?:^|[;&|\n]\s*)yarn\s+deploy(?:\s|$)/i,
];

function output(decision, reason, details = {}) {
  const permissionDecision = decision === "allow" ? "allow" : "deny";
  const payload = {
    decision: permissionDecision,
    reason,
    guardianUnit: details,
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision,
      permissionDecisionReason: reason,
    },
  };
  process.stdout.write(`${JSON.stringify(payload)}\n`);
}

async function readInput() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > MAX_INPUT_BYTES) throw new Error("hook input exceeded 1 MiB");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8").trim();
}

function parseEvent(raw) {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : { command: raw };
  } catch {
    return { command: raw };
  }
}

function stringAt(value, path) {
  let current = value;
  for (const key of path) {
    if (!current || typeof current !== "object") return "";
    current = current[key];
  }
  return typeof current === "string" ? current : "";
}

function commandFrom(event) {
  const paths = [
    ["tool_input", "command"],
    ["tool_input", "cmd"],
    ["toolInput", "command"],
    ["toolInput", "cmd"],
    ["input", "command"],
    ["input", "cmd"],
    ["arguments", "command"],
    ["arguments", "cmd"],
    ["params", "command"],
    ["params", "cmd"],
    ["command"],
    ["cmd"],
  ];
  for (const path of paths) {
    const command = stringAt(event, path);
    if (command) return command;
  }
  return "";
}

function cwdFrom(event) {
  for (const path of [
    ["cwd"],
    ["workdir"],
    ["working_directory"],
    ["tool_input", "cwd"],
    ["tool_input", "workdir"],
    ["input", "workdir"],
    ["arguments", "workdir"],
    ["context", "cwd"],
  ]) {
    const cwd = stringAt(event, path);
    if (cwd) return resolve(cwd);
  }
  return process.cwd();
}

async function hasLauncher(root) {
  try {
    await access(resolve(root, "bin", "guardian-unit.mjs"));
    return true;
  } catch {
    return false;
  }
}

async function findRepositoryRoot(event) {
  const scriptRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const starts = [process.env.GUARDIAN_UNIT_REPO_ROOT, cwdFrom(event), process.cwd(), scriptRoot]
    .filter(Boolean)
    .map((entry) => resolve(entry));

  for (const start of starts) {
    let current = start;
    while (true) {
      if (await hasLauncher(current)) return current;
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  return null;
}

function runGate(root) {
  return new Promise((resolveResult) => {
    const child = spawn(process.execPath, [resolve(root, "bin", "guardian-unit.mjs"), "gate", root], {
      cwd: root,
      env: { ...process.env, NO_COLOR: "1" },
      stdio: ["ignore", "ignore", "ignore"],
    });

    let timedOut = false;
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveResult(result);
    };
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 1_000).unref();
    }, GATE_TIMEOUT_MS);
    timer.unref();

    child.once("error", () => finish({ state: "ERROR" }));
    child.once("close", (code, signal) => {
      if (timedOut) return finish({ state: "TIMEOUT" });
      if (signal) return finish({ state: "ERROR", error: `gate stopped by ${signal}` });
      const states = new Map([[0, "PASS"], [1, "BLOCK"], [2, "WARN"], [3, "HOLD"], [4, "REFUSED"], [5, "ERROR"]]);
      finish({ state: states.get(code) ?? "ERROR", exitCode: code });
    });
  });
}

try {
  const event = parseEvent(await readInput());
  const command = commandFrom(event);
  const matched = DEPLOY_COMMANDS.some((pattern) => pattern.test(command));
  if (!matched) {
    output("allow", "Guardian Unit: unrelated command; release gate not required.", { matched: false });
  } else {
    const root = await findRepositoryRoot(event);
    if (!root) {
      output("deny", "Guardian Unit could not find the repository-local gate. Deployment stopped.", { matched: true, state: "ERROR" });
    } else {
      const result = await runGate(root);
      if (result.state === "PASS" || result.state === "WARN") {
        output("allow", `Guardian Unit ${result.state}: deployment may continue.`, { matched: true, ...result });
      } else {
        output("deny", `Guardian Unit ${result.state}: deployment stopped. Run the gate directly for findings and fixes.`, { matched: true, ...result });
      }
    }
  }
} catch {
  output("deny", "Guardian Unit hook failed before it could prove the deploy safe. Deployment stopped.", {
    matched: true,
    state: "ERROR",
  });
}
