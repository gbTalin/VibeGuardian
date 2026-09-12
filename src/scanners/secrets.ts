import type { RawFinding, RuleDoc, ScanContext, Scanner, Severity } from "../core/types.ts";
import { redactValue, safeSnippet } from "../core/redact.ts";

/**
 * Secret detection.
 *
 * The design goal is precision, not recall. A secrets scanner that fires on
 * every high-entropy string gets muted within a week, and a muted scanner
 * protects nothing. So: named provider patterns first, entropy only as a
 * fallback behind a keyword gate, and an explicit placeholder filter.
 *
 * Two things this scanner does that most do not:
 *
 *  1. It distinguishes secrets that are DESIGNED to be public (a Stripe
 *     publishable key, a Supabase anon key, a Firebase web API key) from
 *     secrets that are not. Flagging the former as critical is the single
 *     fastest way to lose a developer's trust.
 *
 *  2. It escalates severity when the secret sits in code that reaches a
 *     browser. The same key is a moderate problem in a server file and a
 *     five-alarm fire in a React component.
 */

interface Pattern {
  ruleId: string;
  name: string;
  re: RegExp;
  severity: Severity;
  /** This credential type is meant to be published. Report as informational. */
  publicByDesign?: boolean;
  /** Where to rotate it. */
  rotateAt: string;
  /** Which capture group holds the secret material. Defaults to the whole match. */
  group?: number;
}

const PATTERNS: Pattern[] = [
  {
    ruleId: "SECRET-AWS-KEY",
    name: "AWS access key ID",
    re: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,
    severity: "critical",
    rotateAt: "AWS IAM console: deactivate then delete the key, and review CloudTrail for use",
  },
  {
    ruleId: "SECRET-GITHUB-TOKEN",
    name: "GitHub token",
    re: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g,
    severity: "critical",
    rotateAt: "GitHub Settings, Developer settings, Personal access tokens: revoke immediately",
  },
  {
    ruleId: "SECRET-GITLAB-TOKEN",
    name: "GitLab personal access token",
    re: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g,
    severity: "critical",
    rotateAt: "GitLab: User Settings, Access Tokens, revoke",
  },
  {
    ruleId: "SECRET-STRIPE-SECRET",
    name: "Stripe secret key",
    re: /\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b/g,
    severity: "critical",
    rotateAt: "Stripe Dashboard, Developers, API keys: roll the key",
  },
  {
    ruleId: "SECRET-STRIPE-TEST",
    name: "Stripe test key",
    re: /\b((?:sk|rk)_test_[A-Za-z0-9]{16,})\b/g,
    severity: "low",
    rotateAt: "Stripe Dashboard, Developers, API keys: roll the test key",
  },
  {
    ruleId: "SECRET-STRIPE-PUBLISHABLE",
    name: "Stripe publishable key",
    re: /\b(pk_(?:live|test)_[A-Za-z0-9]{16,})\b/g,
    severity: "info",
    publicByDesign: true,
    rotateAt: "No action needed; publishable keys are intended for client code",
  },
  {
    ruleId: "SECRET-OPENAI-KEY",
    name: "OpenAI API key",
    re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,})\b/g,
    severity: "critical",
    rotateAt: "OpenAI platform, API keys: revoke and create a replacement",
  },
  {
    ruleId: "SECRET-ANTHROPIC-KEY",
    name: "Anthropic API key",
    re: /\b(sk-ant-[A-Za-z0-9_-]{24,})\b/g,
    severity: "critical",
    rotateAt: "Anthropic Console, API keys: revoke and create a replacement",
  },
  {
    ruleId: "SECRET-GOOGLE-API-KEY",
    name: "Google API key",
    re: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    severity: "high",
    rotateAt: "Google Cloud Console, APIs and Services, Credentials: regenerate and add referrer restrictions",
  },
  {
    ruleId: "SECRET-SLACK-TOKEN",
    name: "Slack token",
    re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
    severity: "high",
    rotateAt: "Slack app configuration: rotate the token",
  },
  {
    ruleId: "SECRET-SLACK-WEBHOOK",
    name: "Slack incoming webhook URL",
    re: /\b(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_-]+\/B[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+)\b/g,
    severity: "medium",
    rotateAt: "Slack app configuration: delete and recreate the webhook",
  },
  {
    ruleId: "SECRET-SENDGRID-KEY",
    name: "SendGrid API key",
    re: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g,
    severity: "high",
    rotateAt: "SendGrid, Settings, API Keys: delete the key",
  },
  {
    ruleId: "SECRET-TWILIO-KEY",
    name: "Twilio account SID or auth token",
    re: /\b(SK[0-9a-fA-F]{32})\b/g,
    severity: "high",
    rotateAt: "Twilio Console, API keys and tokens: delete the key",
  },
  {
    ruleId: "SECRET-NPM-TOKEN",
    name: "npm access token",
    re: /\b(npm_[A-Za-z0-9]{36})\b/g,
    severity: "critical",
    rotateAt: "npmjs.com, Access Tokens: revoke. A leaked publish token allows malicious package releases",
  },
  {
    ruleId: "SECRET-PRIVATE-KEY",
    name: "Private key block",
    re: /-----BEGIN[ A-Z]*PRIVATE KEY-----/g,
    severity: "critical",
    rotateAt: "Generate a new key pair and revoke or replace the old public key everywhere it is trusted",
  },
  {
    ruleId: "SECRET-DB-CONNECTION",
    name: "Database connection string with embedded password",
    re: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"'`<>]{1,64}:[^\s"'`<>@]{3,}@[^\s"'`<>]+)/gi,
    severity: "critical",
    rotateAt: "Rotate the database user's password and check access logs for connections from unexpected addresses",
  },
  {
    ruleId: "SECRET-JWT",
    name: "JSON Web Token",
    re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    severity: "medium",
    rotateAt: "If this token is still valid, invalidate the session or rotate the signing key",
  },
];

/** Assignment-shaped generic secrets, gated on a keyword so entropy alone never fires. */
const GENERIC_ASSIGNMENT =
  /\b([A-Za-z_][A-Za-z0-9_]{0,40}(?:SECRET|PASSWORD|PASSWD|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|AUTH|CREDENTIAL)[A-Za-z0-9_]{0,20})\s*[:=]\s*['"`]([^'"`\n]{12,120})['"`]/gi;

/** Values that look like secrets but are obviously not. */
const PLACEHOLDER =
  /^(?:x{3,}|y{3,}|\*{3,}|\.{3,}|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|%[A-Z_]+%|your[-_ ]?|my[-_ ]?|test[-_]?|example|sample|dummy|placeholder|changeme|change[-_ ]?me|replace[-_ ]?me|insert[-_ ]?|todo|fixme|none|null|undefined|false|true|abc123|password|secret|foobar|lorem|redacted|hidden|env\.|process\.|os\.environ|configureme|xxxxx)/i;

const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|mocks?|examples?|samples?|docs?|e2e|cypress|playwright)(?:\/|$)|\.(?:test|spec|stories|fixture|example|sample)\.[a-z]+$/i;
const DOC_EXT = /\.(?:md|mdx|markdown|rst|txt|adoc)$/i;

/** File shapes whose contents are shipped to a browser. */
const CLIENT_REACHABLE =
  /(?:^|\/)(?:public|static|assets|client|components?|pages|app|src\/app|views?|www)(?:\/|$)|\.(?:jsx|tsx|vue|svelte|astro)$/i;

/** Env prefixes that frameworks deliberately inline into the client bundle. */
const PUBLIC_ENV_PREFIX = /\b(NEXT_PUBLIC_|VITE_|PUBLIC_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|GATSBY_|VUE_APP_)/;

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function lineOf(text: string, index: number): { line: number; text: string } {
  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < index; i++) {
    if (text[i] === "\n") {
      line++;
      lineStart = i + 1;
    }
  }
  let lineEnd = text.indexOf("\n", lineStart);
  if (lineEnd === -1) lineEnd = text.length;
  return { line, text: text.slice(lineStart, lineEnd) };
}

/** Escalate a secret's severity when it sits in code a browser will receive. */
function clientExposure(file: string, lineText: string): boolean {
  if (PUBLIC_ENV_PREFIX.test(lineText)) return true;
  return CLIENT_REACHABLE.test(file);
}

const RULES: RuleDoc[] = [
  ...PATTERNS.map((p) => ({
    id: p.ruleId,
    title: `${p.name} committed to source`,
    severity: p.severity,
    confidence: "high" as const,
    threat: "Credential theft. Anyone with repository read access, or anyone who opens the shipped JavaScript bundle, obtains a working credential.",
    mappings: { cwe: ["CWE-798", "CWE-540"], owasp: ["A07:2021"], compliance: ["SOC2:CC6.1", "PCI-DSS-4.0:8.3.1", "ISO27001:A.9.4.3"] },
  })),
  {
    id: "SECRET-GENERIC-HIGH-ENTROPY",
    title: "High-entropy value assigned to a credential-named variable",
    severity: "medium",
    confidence: "medium",
    threat: "Credential theft via a secret that does not match a known provider format.",
    mappings: { cwe: ["CWE-798"], owasp: ["A07:2021"], compliance: ["SOC2:CC6.1"] },
  },
  {
    id: "SECRET-CLIENT-EXPOSED",
    title: "Secret placed in code that reaches the browser",
    severity: "critical",
    confidence: "high",
    threat: "The credential is served to every visitor. Opening developer tools is the entire exploit.",
    mappings: { cwe: ["CWE-798", "CWE-200"], owasp: ["A01:2021", "A07:2021"], compliance: ["SOC2:CC6.1"] },
  },
];

export const secretsScanner: Scanner = {
  name: "secrets",
  title: "Leaked credentials",
  description:
    "Finds API keys, tokens, passwords, and private keys that were committed into your code, and tells you where to rotate each one.",
  rules: RULES,

  appliesTo: (ctx) => ctx.files.length > 0,

  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const out: RawFinding[] = [];
    let processed = 0;

    for (const file of ctx.files) {
      if (ctx.signal.aborted) break;
      if (++processed % 500 === 0) ctx.progress(`checked ${processed} files`);

      const text = await ctx.read(file);
      if (!text) continue;

      const isTestish = TEST_PATH.test(file);
      const isDoc = DOC_EXT.test(file);
      const isEnvExample = /\.env\.(?:example|sample|template|dist)$/i.test(file);
      const seenOnLine = new Set<string>();

      for (const p of PATTERNS) {
        p.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = p.re.exec(text)) !== null) {
          const value = m[p.group ?? 1] ?? m[0];
          if (PLACEHOLDER.test(value)) continue;

          const { line, text: lineText } = lineOf(text, m.index);
          const key = `${p.ruleId}:${line}`;
          if (seenOnLine.has(key)) continue;
          seenOnLine.add(key);

          const exposedToClient = clientExposure(file, lineText);
          let severity = p.severity;
          const tags = ["secret", p.name.toLowerCase().replace(/\s+/g, "-")];

          if (p.publicByDesign) {
            severity = "info";
            tags.push("public-by-design");
          } else if (exposedToClient) {
            severity = "critical";
            tags.push("client-exposed");
          } else if (isEnvExample || isDoc) {
            severity = severity === "critical" ? "medium" : "low";
            tags.push("documentation-context");
          } else if (isTestish) {
            severity = severity === "critical" ? "high" : "low";
            tags.push("test-context");
          }

          const redacted = redactValue(value);

          out.push({
            ruleId: p.publicByDesign
              ? p.ruleId
              : exposedToClient
                ? "SECRET-CLIENT-EXPOSED"
                : p.ruleId,
            title: p.publicByDesign
              ? `${p.name} in source (safe by design)`
              : exposedToClient
                ? `${p.name} is being shipped to the browser`
                : `${p.name} committed to source`,
            description: p.publicByDesign
              ? `A ${p.name} appears in ${file}. This key type is designed to be public and safe in client code. Recorded so you know it was seen and deliberately not flagged as a problem.`
              : `A ${p.name} appears in plain text in ${file} at line ${line}. Once a credential is committed, it exists in the repository history forever, and every person and system with read access has a working copy of it.`,
            severity,
            confidence: "high",
            evidence: `${p.name} matching ${redacted} at ${file}:${line}`,
            exploit: p.publicByDesign
              ? "None. This credential type is intended for client-side use and carries no privileged access on its own."
              : exposedToClient
                ? `This file is compiled into the JavaScript sent to every visitor. An attacker opens developer tools, reads the key from the bundle, and calls the API as you. No skill required, no access needed beyond loading the page.`
                : `Anyone with read access to this repository, including every past and future contributor, any CI system, any fork, and anyone who obtains a copy of the git history, can use this credential directly.`,
            remediation: {
              summary: p.publicByDesign
                ? "No action needed."
                : `Remove the value from the code, load it from an environment variable or a secret manager, and rotate it at the provider.`,
              steps: p.publicByDesign
                ? ["Nothing to do. Confirm it is genuinely the publishable key and not the secret one."]
                : [
                    `Replace the literal in ${file}:${line} with a reference to an environment variable or your secret manager.`,
                    exposedToClient
                      ? "Move the call that uses this credential to a server route, an API handler, or an edge function. Client code must never hold a privileged key."
                      : "Confirm the value is supplied at runtime and not baked into any build artifact.",
                    `Rotate the credential. ${p.rotateAt}`,
                    "Review the provider's access logs for use you do not recognise, covering the whole period since the value was first committed.",
                    "Purging git history is optional and does not substitute for rotation. Assume the old value is compromised.",
                  ],
              outOfBandAction: p.publicByDesign
                ? undefined
                : `Rotation is mandatory and is not optional cleanup. ${p.rotateAt}`,
            },
            mappings: {
              cwe: ["CWE-798", "CWE-540"],
              owasp: ["A07:2021"],
              compliance: ["SOC2:CC6.1", "PCI-DSS-4.0:8.3.1", "ISO27001:A.9.4.3"],
            },
            tags,
            location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
          });
        }
      }

      // Generic fallback. Keyword-gated and entropy-gated, so it stays quiet.
      GENERIC_ASSIGNMENT.lastIndex = 0;
      let g: RegExpExecArray | null;
      while ((g = GENERIC_ASSIGNMENT.exec(text)) !== null) {
        const varName = g[1];
        const value = g[2];
        if (PLACEHOLDER.test(value)) continue;
        if (shannonEntropy(value) < 3.5) continue;
        if (/^https?:\/\//i.test(value) && !/:[^@/]+@/.test(value)) continue;
        if (/^[a-z]+(?:[-_][a-z]+){2,}$/i.test(value)) continue; // kebab/snake words, not a key
        if (PATTERNS.some((p) => (p.re.lastIndex = 0, p.re.test(value)))) continue; // already reported precisely

        const { line, text: lineText } = lineOf(text, g.index);
        const exposedToClient = clientExposure(file, lineText);

        out.push({
          ruleId: exposedToClient ? "SECRET-CLIENT-EXPOSED" : "SECRET-GENERIC-HIGH-ENTROPY",
          title: `Possible credential in ${varName}`,
          description: `The variable ${varName} in ${file} is assigned a long, random-looking literal. It does not match a known provider format, so this is a heuristic match rather than a confirmed credential. Confirm before acting.`,
          severity: exposedToClient ? "high" : isTestish || isDoc ? "low" : "medium",
          confidence: "medium",
          evidence: `${varName} assigned ${redactValue(value)} (entropy ${shannonEntropy(value).toFixed(2)}) at ${file}:${line}`,
          exploit: exposedToClient
            ? "If this is a real credential, it is being shipped to browsers and can be read from the page source."
            : "If this is a real credential, everyone with repository access has it.",
          remediation: {
            summary: "Confirm whether this is a live credential. If it is, move it to an environment variable and rotate it.",
            steps: [
              `Open ${file}:${line} and determine whether the value is a real secret or a fixture.`,
              "If it is real: replace it with an environment variable reference and rotate it at the provider.",
              "If it is not: rename the variable so it does not read as a credential, or add it to your suppression list with a reason.",
            ],
          },
          mappings: { cwe: ["CWE-798"], owasp: ["A07:2021"], compliance: ["SOC2:CC6.1"] },
          tags: ["secret", "heuristic", ...(exposedToClient ? ["client-exposed"] : [])],
          location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
        });
      }
    }

    return out;
  },
};
