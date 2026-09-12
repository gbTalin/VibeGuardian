import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

export type ProbeEnvironment = "local" | "staging" | "production";

export interface AuthorizedTarget {
  origin: string;
  url: URL;
  environment: ProbeEnvironment;
  owner: string;
  issuedAt: string;
  expiresAt: string;
  requestBudget: number;
  maxRedirects: number;
  timeoutMs: number;
  ratePerSecond: number;
  corsPreflight: boolean;
  approvedPaths: string[];
  authorizationDigest: string;
}

export class ProbeRefusal extends Error {
  constructor(message: string) {
    super(`REFUSED: ${message}`);
    this.name = "ProbeRefusal";
  }
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ProbeRefusal(`${label} must be a JSON object.`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, allowed: string[], label: string): void {
  const extras = Object.keys(value).filter((key) => !allowed.includes(key));
  if (extras.length > 0) throw new ProbeRefusal(`${label} has unsupported field(s): ${extras.join(", ")}.`);
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) throw new ProbeRefusal(`${label} must be a non-empty string.`);
  return value.trim();
}

function boundedNumber(value: unknown, min: number, max: number, label: string, integer = false): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max || (integer && !Number.isInteger(value))) {
    throw new ProbeRefusal(`${label} must be ${integer ? "an integer" : "a number"} from ${min} through ${max}.`);
  }
  return value;
}

function timestamp(value: unknown, label: string): { source: string; time: number } {
  const source = requiredString(value, label);
  const time = Date.parse(source);
  if (!source.endsWith("Z") || Number.isNaN(time)) throw new ProbeRefusal(`${label} must be an ISO-8601 UTC timestamp ending in Z.`);
  return { source: new Date(time).toISOString(), time };
}

/** Return one exact, normalized origin with no path, query, fragment, or credentials. */
export function normalizeExactOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ProbeRefusal("target must be an exact http(s) origin.");
  }
  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.pathname !== "/" ||
    url.search.length > 0 ||
    url.hash.length > 0 ||
    url.origin !== value
  ) {
    throw new ProbeRefusal("target must be an exact normalized http(s) origin with no credentials, path, query, or fragment.");
  }
  return url.origin;
}

function approvedPaths(value: unknown): string[] {
  if (!Array.isArray(value)) throw new ProbeRefusal("approvedPaths must be an array.");
  const paths = value.map((entry, index) => {
    if (typeof entry !== "string" || !entry.startsWith("/") || entry.startsWith("//")) {
      throw new ProbeRefusal(`approvedPaths[${index}] must begin with exactly one '/'.`);
    }
    if (entry.includes("?") || entry.includes("#") || entry.includes("\\") || /(^|\/)\.\.?($|\/)/.test(entry)) {
      throw new ProbeRefusal(`approvedPaths[${index}] cannot contain a query, fragment, backslash, or traversal segment.`);
    }
    let decoded: string;
    try {
      decoded = decodeURIComponent(entry);
    } catch {
      throw new ProbeRefusal(`approvedPaths[${index}] contains invalid percent encoding.`);
    }
    if (decoded.includes("\\") || /(^|\/)\.\.?($|\/)/.test(decoded) || decoded.startsWith("//") || /^[a-z][a-z0-9+.-]*:/i.test(decoded.slice(1))) {
      throw new ProbeRefusal(`approvedPaths[${index}] is not a safe relative path.`);
    }
    return entry;
  });
  return [...new Set(paths)];
}

function parseTarget(raw: unknown, digest: string, now: Date): AuthorizedTarget {
  const value = object(raw, "target entry");
  exactKeys(
    value,
    [
      "origin",
      "environment",
      "owner",
      "issuedAt",
      "expiresAt",
      "requestBudget",
      "maxRedirects",
      "timeoutMs",
      "ratePerSecond",
      "corsPreflight",
      "approvedPaths",
    ],
    "target entry",
  );
  const origin = normalizeExactOrigin(requiredString(value.origin, "origin"));
  const url = new URL(origin);
  const environment = value.environment;
  if (environment !== "local" && environment !== "staging" && environment !== "production") {
    throw new ProbeRefusal("environment must be local, staging, or production.");
  }
  if (environment !== "local" && url.protocol !== "https:") {
    throw new ProbeRefusal("staging and production targets must use HTTPS.");
  }
  if (environment !== "local" && url.port.length > 0) {
    throw new ProbeRefusal("staging and production targets must use the standard HTTPS port.");
  }
  const issued = timestamp(value.issuedAt, "issuedAt");
  const expires = timestamp(value.expiresAt, "expiresAt");
  if (issued.time > now.getTime()) throw new ProbeRefusal("authorization is not active yet.");
  if (expires.time <= now.getTime()) throw new ProbeRefusal("authorization has expired.");
  if (expires.time <= issued.time) throw new ProbeRefusal("expiresAt must be after issuedAt.");
  if (value.corsPreflight !== undefined && typeof value.corsPreflight !== "boolean") {
    throw new ProbeRefusal("corsPreflight must be a boolean when supplied.");
  }

  return {
    origin,
    url,
    environment,
    owner: requiredString(value.owner, "owner"),
    issuedAt: issued.source,
    expiresAt: expires.source,
    requestBudget: boundedNumber(value.requestBudget, 1, 20, "requestBudget", true),
    maxRedirects: boundedNumber(value.maxRedirects, 0, 5, "maxRedirects", true),
    timeoutMs: boundedNumber(value.timeoutMs, 100, 60_000, "timeoutMs", true),
    ratePerSecond: boundedNumber(value.ratePerSecond, 0.1, 10, "ratePerSecond"),
    corsPreflight: value.corsPreflight ?? false,
    approvedPaths: approvedPaths(value.approvedPaths),
    authorizationDigest: digest,
  };
}

/** Load and validate the project approval before any network request can occur. */
export async function loadAuthorization(path: string, requestedOrigin: string, now = new Date()): Promise<AuthorizedTarget> {
  const origin = normalizeExactOrigin(requestedOrigin);
  let source: string;
  try {
    source = await readFile(path, "utf8");
  } catch {
    throw new ProbeRefusal("authorization record could not be read.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new ProbeRefusal("authorization record is not valid JSON.");
  }
  const document = object(parsed, "authorization record");
  exactKeys(document, ["schemaVersion", "targets"], "authorization record");
  if (document.schemaVersion !== 1) throw new ProbeRefusal("authorization schemaVersion must be 1.");
  if (!Array.isArray(document.targets) || document.targets.length === 0) {
    throw new ProbeRefusal("authorization record must contain at least one target.");
  }
  const digest = createHash("sha256").update(source).digest("hex");
  const candidates: AuthorizedTarget[] = [];
  for (const entry of document.targets) candidates.push(parseTarget(entry, digest, now));
  const target = candidates.find((entry) => entry.origin === origin);
  if (!target) throw new ProbeRefusal("requested target does not exactly match an approved origin.");
  return target;
}
