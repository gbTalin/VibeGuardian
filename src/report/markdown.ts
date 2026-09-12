import type { Finding, ScanResult, Severity } from "../core/types.ts";
import { countBySeverity, postureLabel } from "../core/finding.ts";
import { redactForOutput } from "../core/redact.ts";
import type { GateDecision } from "../gate/types.ts";

/**
 * Human-readable report.
 *
 * The structure is fixed and the limitations section is not optional. A
 * security report that lists findings without stating its own coverage invites
 * the reader to treat "nothing found" as "nothing there", and that inference
 * has caused more harm than most vulnerabilities.
 */

const ICON: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

function findingSection(f: Finding, index: number): string {
  const loc = f.location ? `\`${f.location.file}:${f.location.startLine}\`` : "_(no file location)_";
  const lines: string[] = [
    `### ${index}. ${f.title}`,
    "",
    `| | |`,
    `|---|---|`,
    `| **Severity** | ${ICON[f.severity]} |`,
    `| **Confidence** | ${f.confidence} |`,
    `| **Where** | ${loc} |`,
    `| **Rule** | \`${f.ruleId}\` |`,
    `| **Found by** | ${f.provenance === "deterministic" ? "Deterministic rule" : f.provenance === "hybrid" ? "Deterministic rule, reviewed by an agent" : "Agent analysis"} |`,
  ];

  if (f.mappings.cwe?.length) lines.push(`| **CWE** | ${f.mappings.cwe.join(", ")} |`);
  if (f.mappings.owasp?.length) lines.push(`| **OWASP** | ${f.mappings.owasp.join(", ")} |`);
  if (f.mappings.owaspLlm?.length) lines.push(`| **OWASP LLM** | ${f.mappings.owaspLlm.join(", ")} |`);
  if (f.mappings.advisories?.length) lines.push(`| **Advisories** | ${f.mappings.advisories.slice(0, 8).join(", ")} |`);

  lines.push("", "**What is wrong**", "", f.description, "", "**What an attacker does with it**", "", f.exploit, "");

  if (f.location?.snippet) {
    lines.push("**Evidence**", "", "```", f.location.snippet, "```", "");
  }

  lines.push("**How to fix it**", "", f.remediation.summary, "");
  f.remediation.steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
  lines.push("");

  if (f.remediation.outOfBandAction) {
    lines.push(`> **This needs an action outside the code.** ${f.remediation.outOfBandAction}`, "");
  }

  if (f.remediation.codeFix) {
    if (f.remediation.codeFix.before) {
      lines.push("**Before**", "", "```" + f.remediation.codeFix.language, f.remediation.codeFix.before, "```", "");
    }
    lines.push("**After**", "", "```" + f.remediation.codeFix.language, f.remediation.codeFix.after, "```", "");
  }

  if (f.agentReview) {
    lines.push(
      `**${f.agentReview.agent} reviewed this** (${f.agentReview.model})`,
      "",
      `Verdict: **${f.agentReview.verdict}**`,
      "",
      f.agentReview.reasoning,
      "",
      "_An agent's assessment is advisory. The deterministic finding above stands regardless of this verdict._",
      "",
    );
  }

  lines.push(`_Finding id: \`${f.id}\` — stable across scans, so triage decisions persist._`, "", "---", "");
  return lines.join("\n");
}

export function toMarkdown(result: ScanResult, opts: { title?: string; gate?: GateDecision } = {}): string {
  result = redactForOutput(result);
  const counts = countBySeverity(result.findings);
  const posture = postureLabel(counts);
  const open = result.findings.filter((f) => f.status === "open");

  const out: string[] = [
    `# ${opts.title ?? `Security review: ${result.target.label}`}`,
    "",
    `**${posture.label}.** ${posture.detail}`,
    "",
    `Scanned ${result.coverage.filesScanned.toLocaleString()} files in ${(result.durationMs / 1000).toFixed(1)}s on ${new Date(result.startedAt).toLocaleString()}. Guardian-Unit-Penetration-Testing Agent ${result.guardianUnitVersion}.`,
    "",
    "## Summary",
    "",
    "| Severity | Count |",
    "|---|---|",
    `| Critical | ${counts.critical} |`,
    `| High | ${counts.high} |`,
    `| Medium | ${counts.medium} |`,
    `| Low | ${counts.low} |`,
    `| Informational | ${counts.info} |`,
    `| **Total** | **${result.findings.length}** |`,
    "",
  ];

  if (opts.gate) {
    out.push(
      "## Release decision",
      "",
      `**${opts.gate.outcome}.** ${opts.gate.reasons[0] ?? "Required checks completed with no policy finding."}`,
      "",
      `- Blocking findings: ${opts.gate.blockingFindings.length}`,
      `- Non-blocking findings: ${opts.gate.warningFindings.length}`,
      `- Required evidence failures: ${opts.gate.requiredFailures.length}`,
      "",
    );
  }

  if (open.length > 0) {
    out.push("## Findings", "", "Worst first. Fix in this order.", "");
    open.forEach((f, i) => out.push(findingSection(f, i + 1)));
  } else {
    out.push(
      "## Findings",
      "",
      "No findings matched the rules that ran. Read the coverage section below before concluding anything from that.",
      "",
    );
  }

  const suppressedOrClosed = result.findings.filter((f) => f.status !== "open");
  if (suppressedOrClosed.length > 0) {
    out.push(
      `## Previously triaged (${suppressedOrClosed.length})`,
      "",
      "| Finding | Status | Note |",
      "|---|---|---|",
      ...suppressedOrClosed.map(
        (f) => `| ${f.title} | ${f.status} | ${(f.note ?? "").replace(/\|/g, "\\|").slice(0, 120)} |`,
      ),
      "",
    );
  }

  out.push(
    "## What this scan covered",
    "",
    `- **Files examined:** ${result.coverage.filesScanned.toLocaleString()}`,
    `- **Files skipped:** ${result.coverage.filesSkipped.toLocaleString()}`,
    `- **Checks run:** ${result.coverage.scannersRun.join(", ") || "none"}`,
  );

  if (result.coverage.scannersSkipped.length > 0) {
    out.push(
      `- **Checks not run:**`,
      ...result.coverage.scannersSkipped.map((s) => `  - \`${s.name}\` — ${s.reason}`),
    );
  }

  if (Object.keys(result.coverage.skipReasons).length > 0) {
    out.push("", "Files were skipped for these reasons:", "");
    for (const [reason, n] of Object.entries(result.coverage.skipReasons).sort((a, b) => b[1] - a[1])) {
      out.push(`- ${reason}: ${n.toLocaleString()}`);
    }
  }

  out.push(
    "",
    "## What this scan did not cover",
    "",
    "Read this before reporting the result to anyone.",
    "",
    ...result.coverage.limitations.map((l) => `- ${l}`),
    "",
  );

  if (result.warnings.length > 0) {
    out.push("## Warnings", "", ...result.warnings.map((w) => `- ${w}`), "");
  }

  out.push(
    "---",
    "",
    "_Generated locally by Guardian-Unit-Penetration-Testing Agent. No code, findings, or metadata from this scan left this machine._",
    "",
  );

  return out.join("\n");
}

/** Compact terminal summary. */
export function toTerminal(result: ScanResult, useColor: boolean): string {
  result = redactForOutput(result);
  const c = (code: string, s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
  const counts = countBySeverity(result.findings);
  const posture = postureLabel(counts);
  const open = result.findings.filter((f) => f.status === "open");

  const sevColor: Record<Severity, string> = {
    critical: "1;97;41",
    high: "1;31",
    medium: "1;33",
    low: "36",
    info: "90",
  };

  const lines: string[] = [
    "",
    c("1", `  ${posture.label}`) + c("90", `  ${posture.detail}`),
    "",
  ];

  const top = open.slice(0, 12);
  for (const f of top) {
    const loc = f.location ? `${f.location.file}:${f.location.startLine}` : "—";
    lines.push(
      `  ${c(sevColor[f.severity], ` ${f.severity.toUpperCase().padEnd(8)} `)} ${f.title}`,
      `             ${c("90", loc)}`,
      `             ${c("90", f.remediation.summary)}`,
      "",
    );
  }
  if (open.length > top.length) {
    lines.push(c("90", `  ...and ${open.length - top.length} more.`), "");
  }

  lines.push(
    c(
      "90",
      `  ${counts.critical} critical · ${counts.high} high · ${counts.medium} medium · ${counts.low} low · ${counts.info} info`,
    ),
    c(
      "90",
      `  ${result.coverage.filesScanned.toLocaleString()} files in ${(result.durationMs / 1000).toFixed(1)}s · ${result.coverage.scannersRun.length} checks`,
    ),
    "",
    c("90", "  This scan reads code at rest. It cannot see running systems, and it"),
    c("90", "  does not stop phishing. Nothing found is not the same as nothing there."),
    "",
  );

  return lines.join("\n");
}
