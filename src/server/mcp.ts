import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { buildEngine } from "../scanners/index.ts";
import { loadConfig } from "../core/config.ts";
import { countBySeverity } from "../core/finding.ts";
import { redact, redactForOutput, safeJson } from "../core/redact.ts";
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
] as const;

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

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

export async function startMcpServer(): Promise<void> {
  const engine = buildEngine();
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

  const send = (message: Record<string, unknown>) => {
    // JSON-RPC framing remains one compact JSON document per line; only the
    // payload is transformed at this public-output boundary.
    process.stdout.write(`${safeJson(message)}\n`);
  };
  const reply = (id: JsonRpcRequest["id"], result: unknown) =>
    send({ jsonrpc: "2.0", id, result });
  const fail = (id: JsonRpcRequest["id"], code: number, message: string) =>
    send({ jsonrpc: "2.0", id, error: { code, message: redact(message) } });

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
              "Call security_scan after writing or changing code and before reporting the work " +
              "as complete. Always pass on its coverage limitations to the user; never describe " +
              "code as secure because a scan found nothing.",
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

          if (name !== "security_scan") {
            fail(req.id, -32602, `Unknown tool: ${name}`);
            break;
          }

          const target = resolve(String(args.path ?? process.cwd()));
          const cfg = await loadConfig();
          const only = Array.isArray(args.only) ? (args.only as string[]) : undefined;
          const minSeverity = (args.min_severity as keyof typeof SEV_RANK) ?? "low";

          const result = await engine.scan(target, {
            // Network stays off in MCP mode regardless of configuration. The
            // assistant did not ask the user for permission to make outbound
            // requests, and it is not the assistant's permission to give.
            config: { ...cfg, allowNetwork: false },
            only,
          });

          const filtered = result.findings.filter(
            (f) => SEV_RANK[f.severity] <= SEV_RANK[minSeverity] && f.status === "open",
          );

          reply(req.id, {
            content: [{ type: "text", text: renderFindings(filtered, result.coverage) }],
            structuredContent: {
              scanId: result.scanId,
              target: result.target.id,
              counts: countBySeverity(filtered),
              findings: filtered.map((f) => ({
                id: f.id,
                ruleId: f.ruleId,
                severity: f.severity,
                confidence: f.confidence,
                title: f.title,
                file: f.location?.file ?? null,
                line: f.location?.startLine ?? null,
                remediation: f.remediation.summary,
                cwe: f.mappings.cwe ?? [],
              })),
              coverage: result.coverage,
            },
            isError: false,
          });
          break;
        }

        case "resources/list":
          reply(req.id, { resources: [] });
          break;
        case "prompts/list":
          reply(req.id, { prompts: [] });
          break;

        default:
          if (req.id !== undefined && req.id !== null) {
            fail(req.id, -32601, `Method not found: ${req.method}`);
          }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (req.id !== undefined && req.id !== null) fail(req.id, -32603, message);
      else process.stderr.write(`guardian-unit-mcp: ${redact(message)}\n`);
    }
  }
}
