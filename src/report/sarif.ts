import type { ScanResult, Severity } from "../core/types.ts";
import { VERSION } from "../version.ts";
import { redactForOutput } from "../core/redact.ts";
import type { GateDecision } from "../gate/types.ts";

/**
 * SARIF 2.1.0 output.
 *
 * SARIF is what GitHub code scanning, GitLab, Azure DevOps, and most IDE
 * plugins ingest. Emitting it correctly is the difference between "a tool that
 * prints things" and "a tool that fits into where developers already work".
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

const LEVEL: Record<Severity, "error" | "warning" | "note" | "none"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

/** SARIF wants a 0-10 score; map our severities onto the CVSS-like band. */
const SCORE: Record<Severity, string> = {
  critical: "9.5",
  high: "7.5",
  medium: "5.0",
  low: "3.0",
  info: "0.0",
};

export function toSarif(result: ScanResult, opts: { gate?: GateDecision } = {}): string {
  result = redactForOutput(result);
  const rulesById = new Map<string, ReturnType<typeof ruleDescriptor>>();

  function ruleDescriptor(ruleId: string) {
    const sample = result.findings.find((f) => f.ruleId === ruleId)!;
    const tags = [
      "security",
      ...(sample.mappings.cwe ?? []).map((c) => `external/cwe/${c.toLowerCase()}`),
      ...(sample.mappings.owasp ?? []).map((o) => `OWASP-${o}`),
      ...(sample.mappings.owaspLlm ?? []).map((o) => `OWASP-LLM-${o}`),
      ...sample.tags,
    ];
    return {
      id: ruleId,
      name: ruleId.replace(/[^A-Za-z0-9]/g, ""),
      shortDescription: { text: sample.title },
      fullDescription: { text: sample.description.slice(0, 1000) },
      help: {
        text: `${sample.remediation.summary}\n\n${sample.remediation.steps.map((s, i) => `${i + 1}. ${s}`).join("\n")}`,
        markdown: [
          `**${sample.title}**`,
          "",
          sample.description,
          "",
          `**What an attacker does with it:** ${sample.exploit}`,
          "",
          "**How to fix it**",
          "",
          ...sample.remediation.steps.map((s, i) => `${i + 1}. ${s}`),
          ...(sample.remediation.outOfBandAction
            ? ["", `> ${sample.remediation.outOfBandAction}`]
            : []),
        ].join("\n"),
      },
      defaultConfiguration: { level: LEVEL[sample.severity] },
      properties: {
        tags,
        "security-severity": SCORE[sample.severity],
        precision: sample.confidence === "confirmed" ? "very-high" : sample.confidence,
      },
    };
  }

  for (const f of result.findings) {
    if (!rulesById.has(f.ruleId)) rulesById.set(f.ruleId, ruleDescriptor(f.ruleId));
  }

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Guardian-Unit-Penetration-Testing Agent",
            version: VERSION,
            informationUri: "https://github.com/msitarzewski/agency-agents",
            semanticVersion: VERSION,
            rules: [...rulesById.values()],
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: result.startedAt,
            endTimeUtc: result.finishedAt,
            toolExecutionNotifications: result.warnings.map((w) => ({
              level: "warning" as const,
              message: { text: w },
            })),
          },
        ],
        results: result.findings
          .filter((f) => f.status === "open" || f.status === "triaged")
          .map((f) => ({
            ruleId: f.ruleId,
            level: LEVEL[f.severity],
            message: {
              text: `${f.title}. ${f.remediation.summary}`,
            },
            // Stable identity so code-scanning platforms track a finding across
            // commits instead of reopening it every run.
            partialFingerprints: { guardianUnitFingerprint: f.id },
            properties: {
              provenance: f.provenance,
              confidence: f.confidence,
              ...(f.agentReview ? { agentVerdict: f.agentReview.verdict, agent: f.agentReview.agent } : {}),
            },
            locations: f.location
              ? [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: f.location.file, uriBaseId: "%SRCROOT%" },
                      region: {
                        startLine: Math.max(1, f.location.startLine),
                        endLine: Math.max(f.location.startLine, f.location.endLine),
                        ...(f.location.startColumn ? { startColumn: f.location.startColumn } : {}),
                        ...(f.location.snippet ? { snippet: { text: f.location.snippet } } : {}),
                      },
                    },
                  },
                ]
              : [],
          })),
        // The coverage statement travels with the machine-readable output too,
        // so a dashboard consuming SARIF cannot show findings without it.
        properties: {
          guardianUnitCoverage: result.coverage,
          ...(opts.gate
            ? {
                guardianUnitReleaseGate: {
                  outcome: opts.gate.outcome,
                  blockingFindings: opts.gate.blockingFindings,
                  warningFindings: opts.gate.warningFindings,
                  requiredFailures: opts.gate.requiredFailures,
                },
              }
            : {}),
        },
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
