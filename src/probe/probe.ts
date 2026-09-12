import { materialize, rank } from "../core/finding.ts";
import type { Finding, RawFinding, Severity } from "../core/types.ts";
import type { ProbeObservation, ProbeResult } from "../gate/types.ts";
import { resolveApprovedTarget } from "./address.ts";
import { loadAuthorization, ProbeRefusal, type AuthorizedTarget } from "./authorization.ts";
import { requestPinned } from "./client.ts";

export interface AuthorizedProbeInput {
  authorizationPath: string;
  origin: string;
  now?: Date;
}

interface PlanStep {
  method: "GET" | "OPTIONS";
  url: URL;
  label: string;
  httpRedirectObservation?: boolean;
  headers?: Record<string, string>;
}

const BASE_LIMITATIONS = [
  "The probe was unauthenticated and did not test account or tenant authorization.",
  "The probe did not crawl, submit forms, inject payloads, scan ports or subdomains, or attempt exploitation.",
  "Response bodies and cookie values were discarded and are not present in this output.",
];

function failureMessage(error: unknown): string {
  if (error && typeof error === "object" && "code" in error && typeof error.code === "string") {
    return `network error ${error.code}`;
  }
  const message = error instanceof Error ? error.message : String(error);
  if (/timed out/i.test(message)) return "request timed out";
  return "network request failed";
}

function refused(origin: string, message: string): ProbeResult {
  return {
    state: "REFUSED",
    target: origin,
    requestCount: 0,
    requestBudget: 0,
    observations: [],
    findings: [],
    requiredFailures: [message.replace(/^REFUSED:\s*/, "")],
    limitations: [...BASE_LIMITATIONS, "No network request was issued because target authorization or network safety validation failed."],
  };
}

function planFor(target: AuthorizedTarget): PlanStep[] {
  const steps: PlanStep[] = [{ method: "GET", url: new URL("/", target.origin), label: "root" }];
  if (target.url.protocol === "https:" && target.url.port === "") {
    steps.push({
      method: "GET",
      url: new URL(`http://${target.url.hostname}/`),
      label: "http-root-redirect",
      httpRedirectObservation: true,
    });
  }
  steps.push(
    { method: "GET", url: new URL("/.well-known/security.txt", target.origin), label: "security.txt" },
    { method: "GET", url: new URL("/robots.txt", target.origin), label: "robots.txt" },
  );
  if (target.corsPreflight) {
    steps.push({
      method: "OPTIONS",
      url: new URL("/", target.origin),
      label: "cors-preflight",
      headers: {
        Origin: "https://probe.invalid",
        "Access-Control-Request-Method": "GET",
      },
    });
  }
  return steps;
}

function rawFinding(input: {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: RawFinding["confidence"];
  evidence: string;
  exploit: string;
  fix: string;
  tags?: string[];
}): RawFinding {
  return {
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    severity: input.severity,
    confidence: input.confidence,
    evidence: input.evidence,
    exploit: input.exploit,
    remediation: { summary: input.fix, steps: [input.fix] },
    mappings: { owasp: ["A05:2021"] },
    tags: ["authorized-probe", ...(input.tags ?? [])],
  };
}

function materializeProbeFindings(target: AuthorizedTarget, observations: ProbeObservation[], now: string): Finding[] {
  const findings: Finding[] = [];
  const add = (raw: RawFinding): void => {
    findings.push(
      materialize(raw, {
        source: "authorized-probe",
        target: { kind: "web-surface", id: target.origin, label: target.origin },
        now,
      }),
    );
  };
  const root = observations.find((entry) => entry.method === "GET" && entry.url === `${target.origin}/`);
  const httpRoot = observations.find((entry) => entry.url.startsWith("http://") && target.url.protocol === "https:");
  const securityTxt = observations.find((entry) => entry.url.endsWith("/.well-known/security.txt"));
  const robots = observations.find((entry) => entry.url.endsWith("/robots.txt"));
  const cors = observations.find((entry) => entry.method === "OPTIONS");

  if (root?.tls && !root.tls.authorized) {
    add(
      rawFinding({
        ruleId: "GU-PROBE-TLS-INVALID",
        title: "The live target did not present a valid TLS certificate",
        description: "The approved HTTPS origin completed a TLS connection, but certificate validation failed.",
        severity: "high",
        confidence: "confirmed",
        evidence: `TLS validation failed${root.tls.authorizationError ? `: ${root.tls.authorizationError}` : "."}`,
        exploit: "Visitors cannot reliably authenticate the server, allowing interception warnings or man-in-the-middle risk.",
        fix: "Install a currently valid certificate for the exact approved hostname and verify the full certificate chain.",
        tags: ["tls"],
      }),
    );
  }
  if (target.url.protocol === "https:" && httpRoot) {
    let redirectsToApprovedHttps = false;
    if (httpRoot.redirect) {
      try {
        redirectsToApprovedHttps = new URL(httpRoot.redirect).origin === target.origin;
      } catch {
        redirectsToApprovedHttps = false;
      }
    }
    if (!redirectsToApprovedHttps || !httpRoot.statusCode || httpRoot.statusCode < 300 || httpRoot.statusCode >= 400) {
      add(
        rawFinding({
          ruleId: "GU-PROBE-HTTP-NO-HTTPS-REDIRECT",
          title: "HTTP did not redirect to the approved HTTPS origin",
          description: "The public HTTP root did not provide a redirect to the exact approved HTTPS origin.",
          severity: "medium",
          confidence: "high",
          evidence: `HTTP root returned ${httpRoot.statusCode ?? "no status"} without an approved HTTPS redirect.`,
          exploit: "A visitor who begins on HTTP may remain on an unencrypted connection.",
          fix: "Redirect every HTTP request to the same path on the approved HTTPS origin.",
          tags: ["tls", "redirect"],
        }),
      );
    }
  }

  if (root) {
    const headers = root.headers;
    if (target.url.protocol === "https:" && !headers["strict-transport-security"]) {
      add(rawFinding({ ruleId: "GU-PROBE-MISSING-HSTS", title: "HSTS is missing", description: "The HTTPS root response did not advertise HTTP Strict Transport Security.", severity: "medium", confidence: "high", evidence: "Root response has no Strict-Transport-Security header.", exploit: "Browsers may accept a future downgrade to an unencrypted first connection.", fix: "Add a reviewed Strict-Transport-Security header after confirming all required subdomains support HTTPS.", tags: ["headers"] }));
    }
    if (!headers["content-security-policy"]) {
      add(rawFinding({ ruleId: "GU-PROBE-MISSING-CSP", title: "Content Security Policy is missing", description: "The root response did not provide a Content-Security-Policy header.", severity: "medium", confidence: "medium", evidence: "Root response has no Content-Security-Policy header.", exploit: "A separate injection flaw would have fewer browser-side constraints.", fix: "Deploy a restrictive Content-Security-Policy and test it in report-only mode first.", tags: ["headers"] }));
    }
    if (!headers["x-content-type-options"] || headers["x-content-type-options"].toLowerCase() !== "nosniff") {
      add(rawFinding({ ruleId: "GU-PROBE-MISSING-NOSNIFF", title: "MIME sniffing protection is missing", description: "The root response did not set X-Content-Type-Options to nosniff.", severity: "low", confidence: "high", evidence: "Root response lacks X-Content-Type-Options: nosniff.", exploit: "A browser may interpret some resources as a more dangerous content type.", fix: "Set X-Content-Type-Options: nosniff on application responses.", tags: ["headers"] }));
    }
    if (!headers["x-frame-options"] && !/frame-ancestors/i.test(headers["content-security-policy"] ?? "")) {
      add(rawFinding({ ruleId: "GU-PROBE-MISSING-FRAME-PROTECTION", title: "Frame embedding protection is missing", description: "The root response did not restrict which sites may frame it.", severity: "medium", confidence: "medium", evidence: "Neither X-Frame-Options nor CSP frame-ancestors was observed.", exploit: "An attacker may be able to frame the application for clickjacking.", fix: "Set CSP frame-ancestors (preferred) or X-Frame-Options to the intended framing policy.", tags: ["headers"] }));
    }
    for (const cookie of root.cookieAttributes) {
      if (target.url.protocol === "https:" && !cookie.secure) {
        add(rawFinding({ ruleId: "GU-PROBE-COOKIE-NOT-SECURE", title: "A response cookie lacks Secure", description: "The HTTPS root set a cookie without the Secure attribute.", severity: "medium", confidence: "high", evidence: `Cookie ${cookie.name} lacks the Secure attribute.`, exploit: "The browser may send the cookie over an unencrypted connection.", fix: `Set Secure on ${cookie.name} unless it is intentionally restricted to a non-sensitive local workflow.`, tags: ["headers"] }));
      }
      if (!cookie.httpOnly) {
        add(rawFinding({ ruleId: "GU-PROBE-COOKIE-NOT-HTTPONLY", title: "A response cookie lacks HttpOnly", description: "The root set a cookie without the HttpOnly attribute.", severity: "low", confidence: "medium", evidence: `Cookie ${cookie.name} lacks the HttpOnly attribute.`, exploit: "Injected browser script may be able to read the cookie.", fix: `Set HttpOnly on ${cookie.name} if browser JavaScript does not need to read it.`, tags: ["headers"] }));
      }
      if (!cookie.sameSite) {
        add(rawFinding({ ruleId: "GU-PROBE-COOKIE-NO-SAMESITE", title: "A response cookie lacks SameSite", description: "The root set a cookie without an explicit SameSite policy.", severity: "low", confidence: "medium", evidence: `Cookie ${cookie.name} has no SameSite attribute.`, exploit: "Cross-site requests may include the cookie more broadly than intended.", fix: `Set an explicit SameSite policy on ${cookie.name} that matches the application flow.`, tags: ["headers"] }));
      }
    }
  }

  if (!securityTxt || !securityTxt.statusCode || securityTxt.statusCode < 200 || securityTxt.statusCode >= 300) {
    add(rawFinding({ ruleId: "GU-PROBE-NO-SECURITY-TXT", title: "security.txt was not found", description: "The standard security contact endpoint was absent or did not return success.", severity: "info", confidence: "confirmed", evidence: `security.txt returned ${securityTxt?.statusCode ?? "no status"}.`, exploit: "Security researchers may have difficulty reporting a vulnerability privately.", fix: "Publish /.well-known/security.txt with a monitored Contact and current Expires field.", tags: ["security-txt"] }));
  }
  if (!robots || !robots.statusCode || robots.statusCode < 200 || robots.statusCode >= 300) {
    add(rawFinding({ ruleId: "GU-PROBE-NO-ROBOTS", title: "robots.txt was not found", description: "The conventional robots.txt endpoint was absent or did not return success.", severity: "info", confidence: "confirmed", evidence: `robots.txt returned ${robots?.statusCode ?? "no status"}.`, exploit: "Crawler behavior is not declared; robots.txt is advisory and is never an access control.", fix: "Publish robots.txt only if crawler guidance is useful; never place secrets in it.", tags: ["robots"] }));
  }
  if (cors) {
    const allowOrigin = cors.headers["access-control-allow-origin"];
    const credentials = cors.headers["access-control-allow-credentials"]?.toLowerCase() === "true";
    if (allowOrigin === "https://probe.invalid" && credentials) {
      add(rawFinding({ ruleId: "GU-PROBE-CORS-REFLECTED-CREDENTIALS", title: "CORS accepts an untrusted origin with credentials", description: "The authorized preflight observation accepted the probe's untrusted origin and enabled credentials.", severity: "high", confidence: "confirmed", evidence: "CORS reflected the untrusted probe origin and allowed credentials.", exploit: "A malicious website may be able to read a signed-in user's cross-origin response.", fix: "Allow credentialed CORS only for an exact, reviewed list of trusted application origins.", tags: ["cors"] }));
    } else if (allowOrigin === "*" || allowOrigin === "https://probe.invalid") {
      add(rawFinding({ ruleId: "GU-PROBE-CORS-PERMISSIVE", title: "CORS accepts an untrusted origin", description: "The authorized preflight observation allowed either every origin or the probe's untrusted origin.", severity: "medium", confidence: "high", evidence: `CORS allowed ${allowOrigin === "*" ? "the wildcard origin" : "the untrusted probe origin"}.`, exploit: "Any website may read endpoints that participate in this CORS policy when no other browser restriction applies.", fix: "Restrict CORS to the small set of origins that must call the application.", tags: ["cors"] }));
    }
  }
  if (observations.some((entry) => entry.debugSignature)) {
    add(rawFinding({ ruleId: "GU-PROBE-VERBOSE-ERROR", title: "The live target exposed a verbose error signature", description: "A length-capped response sample matched a generic stack trace or runtime exception signature; the body itself was discarded.", severity: "medium", confidence: "high", evidence: "A generic verbose-error signature was observed; no response text was retained.", exploit: "Runtime error details can reveal implementation information useful to an attacker.", fix: "Return generic client errors and keep full exception details only in access-controlled server logs.", tags: ["errors"] }));
  }
  return rank(findings);
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/** Execute the fixed, non-exploitative request plan after strict authorization. */
export async function runAuthorizedProbe(input: AuthorizedProbeInput): Promise<ProbeResult> {
  let target: AuthorizedTarget;
  try {
    target = await loadAuthorization(input.authorizationPath, input.origin, input.now ?? new Date());
    // Resolve and validate once before the first request. Each request resolves again.
    await resolveApprovedTarget(target);
  } catch (error) {
    if (error instanceof ProbeRefusal) return refused(input.origin, error.message);
    return {
      state: "PARTIAL",
      target: input.origin,
      requestCount: 0,
      requestBudget: 0,
      observations: [],
      findings: [],
      requiredFailures: [`target resolution failed: ${failureMessage(error)}`],
      limitations: [...BASE_LIMITATIONS, "The target could not be resolved, so no network request was issued."],
    };
  }

  const observations: ProbeObservation[] = [];
  const requiredFailures: string[] = [];
  const limitations = [...BASE_LIMITATIONS];
  if (target.approvedPaths.length > 0) {
    limitations.push("approvedPaths were recorded but the hackathon v1 did not request extra paths beyond its fixed safe plan.");
  }
  let requestCount = 0;
  let redirectsFollowed = 0;
  let lastRequestStartedAt = 0;
  const minimumInterval = 1000 / target.ratePerSecond;

  const issue = async (step: PlanStep): Promise<void> => {
    let nextUrl = step.url;
    let first = true;
    while (true) {
      if (requestCount >= target.requestBudget) {
        requiredFailures.push(`request budget exhausted before ${step.label} completed`);
        return;
      }
      const wait = Math.ceil(lastRequestStartedAt + minimumInterval - Date.now());
      if (wait > 0) await delay(wait);
      let resolved;
      try {
        resolved = await resolveApprovedTarget(target);
      } catch (error) {
        if (error instanceof ProbeRefusal) throw error;
        requiredFailures.push(`${step.label}: target re-resolution failed`);
        return;
      }
      lastRequestStartedAt = Date.now();
      requestCount++;
      let observation: ProbeObservation;
      try {
        observation = await requestPinned({
          resolved,
          url: nextUrl,
          method: step.method,
          headers: step.headers,
          httpRedirectObservation: first ? step.httpRedirectObservation : false,
        });
      } catch (error) {
        const message = failureMessage(error);
        observations.push({ method: step.method, url: `${nextUrl.origin}${nextUrl.pathname}`, headers: {}, cookieAttributes: [], error: message });
        requiredFailures.push(`${step.label}: ${message}`);
        return;
      }
      observations.push(observation);
      first = false;
      if (step.httpRedirectObservation || !observation.statusCode || observation.statusCode < 300 || observation.statusCode >= 400 || !observation.redirect) return;
      if (redirectsFollowed >= target.maxRedirects) {
        requiredFailures.push(`${step.label}: redirect limit reached`);
        return;
      }
      let redirect: URL;
      try {
        redirect = new URL(observation.redirect);
      } catch {
        requiredFailures.push(`${step.label}: invalid redirect location`);
        return;
      }
      if (redirect.origin !== target.origin) {
        limitations.push(`${step.label} returned a cross-origin redirect that was not followed.`);
        return;
      }
      redirectsFollowed++;
      nextUrl = redirect;
    }
  };

  try {
    for (const step of planFor(target)) await issue(step);
  } catch (error) {
    if (error instanceof ProbeRefusal) {
      return {
        state: "REFUSED",
        target: target.origin,
        environment: target.environment,
        authorizationDigest: target.authorizationDigest,
        requestCount,
        requestBudget: target.requestBudget,
        observations,
        findings: [],
        requiredFailures: [error.message.replace(/^REFUSED:\s*/, "")],
        limitations: [...limitations, "Probing stopped when a re-resolved address failed network safety validation."],
      };
    }
    requiredFailures.push(failureMessage(error));
  }

  const findings = materializeProbeFindings(target, observations, (input.now ?? new Date()).toISOString());
  return {
    state: requiredFailures.length > 0 ? "PARTIAL" : "COMPLETE",
    target: target.origin,
    environment: target.environment,
    authorizationDigest: target.authorizationDigest,
    requestCount,
    requestBudget: target.requestBudget,
    observations,
    findings,
    requiredFailures: [...new Set(requiredFailures)],
    limitations: [...new Set(limitations)],
  };
}
