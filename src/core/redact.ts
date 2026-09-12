/**
 * Redaction. The single choke point through which any text must pass before it
 * reaches storage, a report, an agent prompt, or the screen.
 *
 * The threat this defends against is mundane and common: a security tool finds
 * a leaked API key, then writes that key into a findings report, which is
 * committed to a repo, pasted into a ticket, or emailed to a vendor. The scan
 * has now leaked the secret further than the original mistake did.
 */

/** Keep enough of a value to recognise it, never enough to use it. */
export function redactValue(value: string): string {
  const v = value.trim();
  if (v.length <= 8) return "*".repeat(Math.max(v.length, 4));
  return `${v.slice(0, 4)}${"*".repeat(Math.min(v.length - 8, 24))}${v.slice(-4)}`;
}

/**
 * High-signal shapes that must never appear in output verbatim, independent of
 * which scanner found them. Deliberately broader than the detection rules:
 * detection optimizes for precision, redaction optimizes for recall.
 */
const HARD_REDACT: { name: string; re: RegExp }[] = [
  { name: "aws-access-key", re: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g },
  { name: "github-token", re: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g },
  { name: "gitlab-token", re: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g },
  { name: "slack-token", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g },
  { name: "stripe-key", re: /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b/g },
  { name: "openai-key", re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})\b/g },
  { name: "anthropic-key", re: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g },
  { name: "google-api-key", re: /\b(AIza[0-9A-Za-z_-]{35})\b/g },
  { name: "sendgrid-key", re: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g },
  { name: "npm-token", re: /\b(npm_[A-Za-z0-9]{36})\b/g },
  { name: "jwt", re: /\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g },
  {
    name: "private-key-block",
    re: /-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----/g,
  },
  {
    name: "connection-string",
    re: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"'`<>]*:[^\s"'`<>@]+@[^\s"'`<>]+)/gi,
  },
  { name: "basic-auth-url", re: /\bhttps?:\/\/[^\s"'`<>/]+:[^\s"'`<>@]+@[^\s"'`<>]+/gi },
];

/**
 * Scrub any recognised secret shape from arbitrary text.
 * Applied to every snippet, evidence string, log line, and agent prompt.
 */
export function redact(text: string): string {
  if (!text) return text;
  let out = text;
  for (const { name, re } of HARD_REDACT) {
    out = out.replace(re, (m) => {
      if (name === "private-key-block") return "[REDACTED PRIVATE KEY BLOCK]";
      return redactValue(m);
    });
  }
  return out;
}

/**
 * Trim a snippet to a safe size and redact it. Long snippets are how whole
 * config files end up in a report.
 */
export function safeSnippet(text: string, maxLen = 240): string {
  const oneLine = text.replace(/\r?\n/g, "\\n");
  const trimmed = oneLine.length > maxLen ? `${oneLine.slice(0, maxLen)}...` : oneLine;
  return redact(trimmed);
}

/**
 * Apply redaction at an output boundary, including nested warning, triage, and
 * report fields. Scanner-level redaction is necessary but not sufficient:
 * provider and storage errors can be introduced after a scanner has finished.
 */
export function redactForOutput<T>(value: T): T {
  if (typeof value === "string") return redact(value) as T;
  if (Array.isArray(value)) return value.map((entry) => redactForOutput(entry)) as T;
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, redactForOutput(entry)]),
    ) as T;
  }
  return value;
}

/** Serialize a result only after recursively redacting every user-visible field. */
export function safeJson(value: unknown, space?: number): string {
  return JSON.stringify(redactForOutput(value), null, space);
}

/** Reduce an absolute path to the scan-relative portion. Absolute paths leak usernames into reports. */
export function relativize(absPath: string, root: string): string {
  const normRoot = root.endsWith("/") ? root : `${root}/`;
  return absPath.startsWith(normRoot) ? absPath.slice(normRoot.length) : absPath;
}
