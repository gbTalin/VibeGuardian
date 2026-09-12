import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { buildEngine } from "../scanners/index.ts";
import { loadConfig } from "../core/config.ts";
import { countBySeverity } from "../core/finding.ts";
import { redact, redactForOutput, safeJson } from "../core/redact.ts";
import { runGate } from "../gate/run.ts";
import type { ReleaseReceipt } from "../gate/types.ts";
import { VERSION } from "../version.ts";
import type { Finding } from "../core/types.ts";

/**
 * Guardian-Unit-Penetration-Testing Agent as an MCP server.
 *
 * This exists because of where the vulnerabilities come from. The assistant
 * that wrote the code is the thing best placed to check it, at the moment it
 * finishes writing — before the developer has moved on, while the reasoning is
 * still in context, and while a fix costs one edit instead of one sprint.
 *
 * Implemented over stdio with a hand-rolled JSON-RPC loop rather than the
 * official SDK, to hold the zero-dependency line. A security tool should not
 * be the largest supply-chain risk its user takes on this week.
 *
 * Protocol: https://modelcontextprotocol.io/specification
 */

const PROTOCOL_VERSION = "2025-06-18";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}

const TOOLS = [
  {
    name: "security_scan",
    title: "Scan code for security problems",
    description:
      "Run Guardian-Unit-Penetration-Testing Agent's local security scanners over a folder and return the findings, worst first. " +
      "Detects leaked credentials, the access-control mistakes AI assistants make by default " +
      "(row-level security disabled, privileged keys in browser code, permission checks on " +
      "client-editable fields), prompt-injection paths, risky MCP server configuration, " +
      "dependency and supply-chain risk, CI pipeline flaws, infrastructure misconfiguration, " +
      "and injection vulnerabilities. Runs entirely on this machine: no code is uploaded and " +
      "no network request is made. Call this after writing or modifying code, before telling " +
      "the user the work is done.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the folder to scan. Defaults to the working directory.",
        },
        only: {
          type: "array",
          items: { type: "string" },
          description:
            "Restrict to these scanners: secrets, ai-code, ai-agents, dependencies, ci, iac, code.",
        },
        min_severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low", "info"],
          description: "Omit findings below this severity. Defaults to low.",
        },
      },
    },
  },
  {
    name: "security_rules",
    title: "List available security checks",
    description:
      "List every rule Guardian-Unit-Penetration-Testing Agent can apply, with its severity, the threat it addresses, and its " +
      "CWE and OWASP mappings. Use this to explain what was and was not checked.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "guardian_security_scan",
    title: "Guardian Unit security scan",
    description:
      "Run the local, network-off Guardian Unit source and configuration checks. " +
      "This tool reads the selected repository and returns findings with honest coverage limits; it does not modify code or exploit anything.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the repository. Defaults to the working directory.",
        },
        only: {
          type: "array",
          items: { type: "string" },
          description: "Optional scanner names to run.",
        },
        min_severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low", "info"],
          description: "Omit findings below this severity. Defaults to low.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "guardian_release_gate",
    title: "Guardian Unit release gate",
    description:
      "Return PASS, WARN, HOLD, or BLOCK for a repository. Static checks are local. " +
      "A live URL is probed only when both an exact target and an authorization-record path are supplied and validated by the shared gate.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute path to the repository. Defaults to the working directory.",
        },
        target: {
          type: "string",
          description: "Optional exact authorized http(s) origin to probe.",
        },
        authorization_path: {
          type: "string",
          description: "Authorization record for target. Required whenever target is supplied.",
        },
        block_at_or_above: {
          type: "string",
          enum: ["critical", "high", "medium", "low", "info"],
          description: "Optional release threshold. Defaults to high.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "guardian_get_receipt",
    title: "Get Guardian Unit release receipt",
    description:
      "Retrieve a redacted release receipt created by guardian_release_gate during this MCP session. " +
      "This tool does not read arbitrary files or perform a new scan.",
    inputSchema: {
      type: "object",
      properties: {
        receipt_id: {
          type: "string",
          description: "Receipt digest or scan id. Omit for the most recent receipt in this MCP session.",
        },
      },
      additionalProperties: false,
    },
  },
] as const;

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
type SecurityEngine = ReturnType<typeof buildEngine>;
const receipts = new Map<string, ReleaseReceipt>();
let latestReceiptId: string | null = null;

/** Public JSON-RPC boundary, exported for deterministic protocol testing. */
export function serializeMcpMessage(message: Record<string, unknown>): string {
  return safeJson(message);
}

/** Public diagnostic boundary; stdout framing is not available for notifications. */
export function formatMcpDiagnostic(message: string): string {
  return `guardian-unit-mcp: ${redact(message)}\n`;
}

/** Render findings as text an assistant can act on directly. */
function renderFindings(findings: Finding[], coverage: { filesScanned: number; limitations: string[] }): string {
  findings = redactForOutput(findings);
  coverage = redactForOutput(coverage);
  if (findings.length === 0) {
    return [
      "No findings matched the rules that ran.",
      "",
      `Files examined: ${coverage.filesScanned}.`,
      "",
      "Important: this means no rule matched, which is not the same as the code being secure.",
      "State that distinction to the user rather than reporting the code as safe.",
    ].join("\n");
  }

  const counts = countBySeverity(findings);
  const out: string[] = [
    `${findings.length} findings: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info.`,
    `Files examined: ${coverage.filesScanned}.`,
    "",
    "Fix in this order.",
    "",
  ];

  findings.forEach((f, i) => {
    out.push(
      `## ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}`,
      `- Rule: ${f.ruleId} (confidence: ${f.confidence}, source: ${f.provenance})`,
      ...(f.location ? [`- Location: ${f.location.file}:${f.location.startLine}`] : []),
      ...(f.mappings.cwe?.length ? [`- ${f.mappings.cwe.join(", ")}`] : []),
      "",
      f.description,
      "",
      `Impact: ${f.exploit}`,
      "",
      `Fix: ${f.remediation.summary}`,
      ...f.remediation.steps.map((s, n) => `  ${n + 1}. ${s}`),
      ...(f.remediation.outOfBandAction
        ? ["", `ACTION OUTSIDE THE CODE: ${f.remediation.outOfBandAction}`]
        : []),
      ...(f.remediation.codeFix
        ? ["", "Suggested fix:", "```" + f.remediation.codeFix.language, f.remediation.codeFix.after, "```"]
        : []),
      "",
    );
  });

  out.push(
    "---",
    "What this scan could not see:",
    ...coverage.limitations.map((l) => `- ${l}`),
    "",
    "Report these limits to the user alongside the findings. Do not describe the code as secure.",
  );

  return out.join("\n");
}

/** Shared in-process scan adapter used by both the legacy and Guardian-named MCP tools. */
export async function runMcpSecurityScan(
  engine: SecurityEngine,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const target = resolve(String(args.path ?? process.cwd()));
  const cfg = await loadConfig();
  const only = Array.isArray(args.only) ? (args.only as string[]) : undefined;
  const requestedSeverity = String(args.min_severity ?? "low");
  const minSeverity = Object.hasOwn(SEV_RANK, requestedSeverity)
    ? requestedSeverity as keyof typeof SEV_RANK
    : "low";

  const result = await engine.scan(target, {
    // A general MCP scan never grants network permission.
    config: { ...cfg, allowNetwork: false },
    only,
  });
  const filtered = result.findings.filter(
    (finding) => SEV_RANK[finding.severity] <= SEV_RANK[minSeverity] && finding.status === "open",
  );

  return {
    content: [{ type: "text", text: renderFindings(filtered, result.coverage) }],
    structuredContent: {
      scanId: result.scanId,
      target: result.target.id,
      counts: countBySeverity(filtered),
      findings: filtered.map((finding) => ({
        id: finding.id,
        ruleId: finding.ruleId,
        severity: finding.severity,
        confidence: finding.confidence,
        title: finding.title,
        file: finding.location?.file ?? null,
        line: finding.location?.startLine ?? null,
        remediation: finding.remediation.summary,
        cwe: finding.mappings.cwe ?? [],
      })),
      coverage: result.coverage,
      evidenceState: "COMPLETE",
    },
    isError: false,
  };
}

/** Shared gate adapter. It calls the engine directly; no CLI subprocess is spawned. */
export async function runMcpReleaseGate(args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const root = resolve(String(args.path ?? process.cwd()));
  const target = typeof args.target === "string" && args.target.trim() ? args.target.trim() : undefined;
  const authorizationPath = typeof args.authorization_path === "string" && args.authorization_path.trim()
    ? resolve(root, args.authorization_path.trim())
    : undefined;
  if (Boolean(target) !== Boolean(authorizationPath)) {
    throw new Error("target and authorization_path must be supplied together");
  }

  const threshold = String(args.block_at_or_above ?? "");
  const policy = Object.hasOwn(SEV_RANK, threshold)
    ? { blockAtOrAbove: threshold as keyof typeof SEV_RANK }
    : undefined;
  // target/authorizationPath are consumed by the shared authorized-probe path.
  // Keeping the object inferred allows older static-only builds to start while
  // preserving fail-closed behavior when a target is requested.
  const gateOptions = { root, policy, target, authorizationPath } as Parameters<typeof runGate>[0];
  const gate = await runGate(gateOptions);
  const receipt = redactForOutput(gate.receipt);
  receipts.set(receipt.digest, receipt);
  receipts.set(receipt.scan.id, receipt);
  latestReceiptId = receipt.digest;

  const mayDeploy = !gate.termination && (gate.decision.outcome === "PASS" || gate.decision.outcome === "WARN");
  const probe = (gate as typeof gate & { probe?: { state?: string } }).probe;
  const scannerFailed = receipt.scan.coverage.scannersSkipped.some((scanner) => scanner.reason.startsWith("error:"));
  const evidence = {
    sourceAndConfig: scannerFailed ? "UNPROVEN" : "COMPLETE",
    liveProbe: target ? (probe?.state ?? (gate.termination === "REFUSED" ? "REFUSED" : "UNPROVEN")) : "UNPROVEN",
    intelligence: receipt.intelligence.state,
  };
  const text = [
    `Guardian Unit release decision: ${gate.termination ?? gate.decision.outcome}.`,
    mayDeploy ? "Deployment may continue." : "Deployment must stop.",
    ...gate.decision.reasons.map((reason) => `- ${reason}`),
    `Receipt: ${receipt.digest}`,
    `Evidence: source/config ${evidence.sourceAndConfig}; live probe ${evidence.liveProbe}; threat intelligence ${evidence.intelligence}.`,
  ].join("\n");

  return {
    content: [{ type: "text", text }],
    structuredContent: {
      outcome: gate.decision.outcome,
      termination: gate.termination ?? null,
      mayDeploy,
      reasons: gate.decision.reasons,
      blockingFindings: gate.decision.blockingFindings,
      warningFindings: gate.decision.warningFindings,
      evidence,
      receiptId: receipt.digest,
      scanId: receipt.scan.id,
      coverage: receipt.scan.coverage,
    },
    isError: false,
  };
}

/** In-session receipt lookup deliberately cannot read an arbitrary caller-supplied path. */
export function getMcpReceipt(args: Record<string, unknown>): Record<string, unknown> {
  const requested = typeof args.receipt_id === "string" && args.receipt_id.trim()
    ? args.receipt_id.trim()
    : latestReceiptId;
  const receipt = requested ? receipts.get(requested) : undefined;
  if (!receipt) {
    return {
      content: [{ type: "text", text: "No matching release receipt exists in this MCP session. Run guardian_release_gate first." }],
      structuredContent: { receipt: null, evidenceState: "UNPROVEN" },
      isError: true,
    };
  }
  return {
    content: [{ type: "text", text: safeJson(receipt, 2) }],
    structuredContent: { receipt },
    isError: false,
  };
}

export async function startMcpServer(): Promise<void> {
  const engine = buildEngine();
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

  const send = (message: Record<string, unknown>) => {
    // JSON-RPC framing remains one compact JSON document per line; only the
    // payload is transformed at this public-output boundary.
    process.stdout.write(`${serializeMcpMessage(message)}\n`);
  };
  const reply = (id: JsonRpcRequest["id"], result: unknown) =>
    send({ jsonrpc: "2.0", id, result });
  const fail = (id: JsonRpcRequest["id"], code: number, message: string) =>
    send({ jsonrpc: "2.0", id, error: { code, message: redact(message) } });
  const failRequest = (req: JsonRpcRequest, code: number, message: string) => {
    // JSON-RPC notifications never receive a response. Keep their failures on
    // stderr so stdout remains a valid JSON Lines protocol stream.
    if (req.id === undefined) process.stderr.write(formatMcpDiagnostic(message));
    else fail(req.id, code, message);
  };

  // Diagnostics go to stderr. Anything on stdout that is not a JSON-RPC
  // message corrupts the transport.
  process.stderr.write(`Guardian-Unit-Penetration-Testing Agent MCP server ${VERSION} ready (${engine.ruleCount()} checks)\n`);

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let req: JsonRpcRequest;
    try {
      req = JSON.parse(trimmed) as JsonRpcRequest;
    } catch {
      fail(null, -32700, "Parse error");
      continue;
    }

    try {
      switch (req.method) {
        case "initialize":
          reply(req.id, {
            protocolVersion: PROTOCOL_VERSION,
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: "guardian-unit", version: VERSION },
            instructions:
              "Guardian-Unit-Penetration-Testing Agent scans code for security problems entirely on this machine. " +
              "Call guardian_release_gate before deployment. PASS and WARN may continue; HOLD, BLOCK, " +
              "REFUSED, ERROR, timeout, or unreadable evidence must stop. Always pass on coverage " +
              "limitations; never describe code as secure because a scan found nothing.",
          });
          break;

        case "notifications/initialized":
        case "notifications/cancelled":
          break; // notifications carry no id and take no response

        case "ping":
          reply(req.id, {});
          break;

        case "tools/list":
          reply(req.id, { tools: TOOLS });
          break;

        case "tools/call": {
          const name = String(req.params?.name ?? "");
          const args = (req.params?.arguments ?? {}) as Record<string, unknown>;

          if (name === "security_rules") {
            const text = engine
              .list()
              .map(
                (s) =>
                  `## ${s.title} (${s.name})\n${s.description}\n\n` +
                  s.rules
                    .map(
                      (r) =>
                        `- [${r.severity}] ${r.id}: ${r.title}\n  Threat: ${r.threat}` +
                        (r.mappings.cwe?.length ? `\n  ${r.mappings.cwe.join(", ")}` : ""),
                    )
                    .join("\n"),
              )
              .join("\n\n");
            reply(req.id, { content: [{ type: "text", text }] });
            break;
          }

          if (name === "security_scan" || name === "guardian_security_scan") {
            reply(req.id, await runMcpSecurityScan(engine, args));
            break;
          }

          if (name === "guardian_release_gate") {
            reply(req.id, await runMcpReleaseGate(args));
            break;
          }

          if (name === "guardian_get_receipt") {
            reply(req.id, getMcpReceipt(args));
            break;
          }

          failRequest(req, -32602, `Unknown tool: ${name}`);
          break;
        }

        case "resources/list":
          reply(req.id, { resources: [] });
          break;
        case "prompts/list":
          reply(req.id, { prompts: [] });
          break;

        default:
          failRequest(req, -32601, `Method not found: ${req.method}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      failRequest(req, -32603, message);
    }
  }
}
