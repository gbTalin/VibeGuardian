import { request as httpRequest, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { TLSSocket } from "node:tls";
import type { ProbeCookieObservation, ProbeObservation, ProbeTlsObservation } from "../gate/types.ts";
import type { ResolvedTarget } from "./address.ts";
import { ProbeRefusal } from "./authorization.ts";

const BODY_READ_CAP = 32 * 1024;
const SAFE_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
  "cache-control",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "content-type",
] as const;

export interface PinnedRequestInput {
  resolved: ResolvedTarget;
  url: URL;
  method: "GET" | "OPTIONS";
  headers?: Record<string, string>;
  /** The sole scheme-changing request: observe HTTP root for an approved HTTPS host. */
  httpRedirectObservation?: boolean;
}

function normalizeVisibleUrl(url: URL): string {
  return `${url.origin}${url.pathname}`;
}

function textHeader(value: string | string[] | undefined): string | undefined {
  if (value === undefined) return undefined;
  return (Array.isArray(value) ? value.join(", ") : value).slice(0, 1024);
}

function normalizedHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const name of SAFE_HEADERS) {
    const value = textHeader(headers[name]);
    if (value !== undefined) result[name] = value;
  }
  return result;
}

function cookieAttributes(values: string[] | undefined): ProbeCookieObservation[] {
  if (!values) return [];
  return values.map((source, index) => {
    const parts = source.split(";");
    const equals = parts[0].indexOf("=");
    const candidate = equals > 0 ? parts[0].slice(0, equals).trim() : `cookie-${index + 1}`;
    const name = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/.test(candidate) ? candidate : `cookie-${index + 1}`;
    const attributes = parts.slice(1).map((part) => part.trim());
    const sameSiteSource = attributes.find((part) => /^samesite=/i.test(part))?.split("=", 2)[1]?.toLowerCase();
    const sameSite = sameSiteSource === "strict" ? "Strict" : sameSiteSource === "lax" ? "Lax" : sameSiteSource === "none" ? "None" : undefined;
    return {
      name,
      secure: attributes.some((part) => /^secure$/i.test(part)),
      httpOnly: attributes.some((part) => /^httponly$/i.test(part)),
      ...(sameSite ? { sameSite } : {}),
    };
  });
}

function tlsObservation(socket: unknown): ProbeTlsObservation | undefined {
  if (!(socket instanceof TLSSocket)) return undefined;
  const certificate = socket.getPeerCertificate();
  const authorizationError = socket.authorizationError ? String(socket.authorizationError) : undefined;
  return {
    authorized: socket.authorized,
    ...(authorizationError ? { authorizationError: authorizationError.slice(0, 240) } : {}),
    ...(socket.getProtocol() ? { protocol: socket.getProtocol() ?? undefined } : {}),
    ...(socket.alpnProtocol ? { alpnProtocol: socket.alpnProtocol } : {}),
    ...(certificate.valid_from ? { validFrom: certificate.valid_from } : {}),
    ...(certificate.valid_to ? { validTo: certificate.valid_to } : {}),
  };
}

function validateRequestScope(input: PinnedRequestInput): void {
  const approved = input.resolved.target.url;
  if (input.url.username || input.url.password || input.url.hash) throw new ProbeRefusal("request URL contains credentials or a fragment.");
  const normal = input.url.origin === approved.origin;
  const httpObservation =
    input.httpRedirectObservation === true &&
    approved.protocol === "https:" &&
    input.url.protocol === "http:" &&
    input.url.hostname === approved.hostname &&
    input.url.port === "" &&
    input.url.pathname === "/" &&
    input.url.search === "";
  if (!normal && !httpObservation) throw new ProbeRefusal("request escaped the exact approved origin.");
}

/** One bounded request. Redirect policy and request budgets live in probe.ts. */
export async function requestPinned(input: PinnedRequestInput): Promise<ProbeObservation> {
  validateRequestScope(input);
  const { pinned, target } = input.resolved;
  const hostname = target.url.hostname.startsWith("[") ? target.url.hostname.slice(1, -1) : target.url.hostname;
  const options: RequestOptions = {
    protocol: input.url.protocol,
    hostname,
    port: input.url.port || undefined,
    path: `${input.url.pathname}${input.url.search}`,
    method: input.method,
    agent: false,
    maxHeaderSize: 32 * 1024,
    headers: {
      "User-Agent": "Guardian-Unit/0.1 authorized-safe-probe",
      Accept: "*/*",
      Connection: "close",
      Host: input.url.host,
      ...input.headers,
    },
    lookup: (_host, _options, callback) => callback(null, pinned.address, pinned.family),
    ...(input.url.protocol === "https:"
      ? {
          servername: isIP(hostname) === 0 ? hostname : undefined,
          // Observe invalid certificates as blocking evidence instead of hiding
          // the result behind a generic transport error.
          rejectUnauthorized: false,
        }
      : {}),
  };

  return await new Promise<ProbeObservation>((resolve, reject) => {
    const request = input.url.protocol === "https:" ? httpsRequest(options) : httpRequest(options);
    let settled = false;
    const finish = (value: ProbeObservation): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => request.destroy(new Error(`request timed out after ${target.timeoutMs}ms`)), target.timeoutMs);
    request.once("error", (error) => {
      if (settled) return;
      clearTimeout(timer);
      reject(error);
    });
    request.once("response", (response) => {
      const observation: ProbeObservation = {
        method: input.method,
        url: normalizeVisibleUrl(input.url),
        statusCode: response.statusCode,
        headers: normalizedHeaders(response.headers),
        cookieAttributes: cookieAttributes(response.headers["set-cookie"]),
        ...(input.url.protocol === "https:" ? { tls: tlsObservation(response.socket) } : {}),
      };
      const location = textHeader(response.headers.location);
      if (location) {
        try {
          const redirect = new URL(location, input.url);
          observation.redirect = normalizeVisibleUrl(redirect);
        } catch {
          observation.redirect = "invalid-location";
        }
      }
      let bytesRead = 0;
      let tail = "";
      let debug = false;
      response.on("data", (chunk: Buffer | string) => {
        if (settled) return;
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const remaining = BODY_READ_CAP - bytesRead;
        const sample = buffer.subarray(0, Math.max(0, remaining));
        bytesRead += sample.length;
        tail = `${tail}${sample.toString("utf8")}`.slice(-1024);
        if (/stack trace|uncaught exception|sql syntax|referenceerror:|traceback \(most recent call last\)/i.test(tail)) debug = true;
        if (buffer.length > remaining || bytesRead >= BODY_READ_CAP) {
          observation.bodyTruncated = true;
          if (debug) observation.debugSignature = "generic-error-signature";
          response.destroy();
          finish(observation);
        }
      });
      response.once("end", () => {
        if (debug) observation.debugSignature = "generic-error-signature";
        finish(observation);
      });
      response.once("error", (error) => {
        if (!settled) reject(error);
      });
    });
    request.end();
  });
}
