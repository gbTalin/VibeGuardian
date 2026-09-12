import type { RawFinding, RuleDoc, ScanContext, Scanner } from "../core/types.ts";

/**
 * External web surface.
 *
 * The only scanner that touches the network, and it is off unless the operator
 * explicitly allows it. It performs read-only requests against hosts the
 * operator names -- it never probes, fuzzes, or attempts exploitation, because
 * a tool that scans hosts on a user's behalf must never do anything the user
 * could not defend as authorized activity against their own property.
 *
 * Targets come from GUARDIAN_UNIT_DOMAINS or the --domain flag. Guardian Unit deliberately
 * does NOT harvest hostnames out of source code and probe them automatically:
 * a config file frequently names a partner's or a customer's host, and scanning
 * those without authorization is somebody else's incident.
 */

const RULES: RuleDoc[] = [
  {
    id: "SURF-NO-HSTS",
    title: "Strict-Transport-Security header missing",
    severity: "medium",
    confidence: "confirmed",
    threat: "A first visit over plain HTTP can be intercepted and downgraded.",
    mappings: { cwe: ["CWE-319"], owasp: ["A02:2021"], compliance: ["SOC2:CC6.7", "PCI-DSS-4.0:4.2.1"] },
  },
  {
    id: "SURF-NO-CSP",
    title: "Content-Security-Policy header missing",
    severity: "medium",
    confidence: "confirmed",
    threat: "Removes the main defence that limits the damage of a cross-site scripting flaw.",
    mappings: { cwe: ["CWE-1021"], owasp: ["A05:2021"] },
  },
  {
    id: "SURF-WEAK-CSP",
    title: "Content-Security-Policy permits unsafe inline or eval",
    severity: "low",
    confidence: "confirmed",
    threat: "A policy allowing unsafe-inline provides little protection against injected script.",
    mappings: { cwe: ["CWE-1021"], owasp: ["A05:2021"] },
  },
  {
    id: "SURF-MISSING-HEADERS",
    title: "Common protective response header missing",
    severity: "low",
    confidence: "confirmed",
    threat: "Clickjacking and MIME-sniffing attacks that the header would prevent.",
    mappings: { cwe: ["CWE-1021", "CWE-693"], owasp: ["A05:2021"] },
  },
  {
    id: "SURF-SERVER-BANNER",
    title: "Response headers disclose server software and version",
    severity: "info",
    confidence: "confirmed",
    threat: "Tells an attacker exactly which published exploits to try first.",
    mappings: { cwe: ["CWE-200"], owasp: ["A05:2021"] },
  },
  {
    id: "SURF-NO-HTTPS-REDIRECT",
    title: "Plain HTTP does not redirect to HTTPS",
    severity: "high",
    confidence: "confirmed",
    threat: "Traffic including credentials and session cookies can travel unencrypted.",
    mappings: { cwe: ["CWE-319"], owasp: ["A02:2021"], compliance: ["PCI-DSS-4.0:4.2.1"] },
  },
  {
    id: "SURF-EXPOSED-PATH",
    title: "Sensitive path is publicly reachable",
    severity: "high",
    confidence: "high",
    threat: "Configuration files, version control data, and admin panels exposed to the internet.",
    mappings: { cwe: ["CWE-200", "CWE-538"], owasp: ["A01:2021", "A05:2021"] },
  },
  {
    id: "SURF-CORS-PERMISSIVE",
    title: "Response allows any origin with credentials",
    severity: "high",
    confidence: "confirmed",
    threat: "Any website can make authenticated requests on a visitor's behalf.",
    mappings: { cwe: ["CWE-942"], owasp: ["A05:2021"] },
  },
];

/**
 * Paths checked with a single GET each. All are things that should never be
 * served publicly and that are checked by every attacker's first automated
 * sweep. A 200 with plausible content is the finding; anything else is silence.
 */
const SENSITIVE_PATHS: { path: string; what: string; confirm: RegExp; severity: "critical" | "high" | "medium" }[] = [
  { path: "/.env", what: "environment file", confirm: /^[A-Z_]+=|\bAPI_KEY\b|\bSECRET\b|\bDATABASE_URL\b/m, severity: "critical" },
  { path: "/.git/config", what: "git repository configuration", confirm: /\[core\]|\[remote /, severity: "critical" },
  { path: "/.git/HEAD", what: "git repository data", confirm: /^ref:\s+refs\//, severity: "critical" },
  { path: "/config.json", what: "application configuration", confirm: /[{[]/, severity: "medium" },
  { path: "/.aws/credentials", what: "AWS credential file", confirm: /aws_access_key_id/i, severity: "critical" },
  { path: "/.npmrc", what: "npm configuration", confirm: /_authToken|registry=/, severity: "high" },
  { path: "/wp-config.php.bak", what: "WordPress configuration backup", confirm: /DB_PASSWORD|define\(/, severity: "critical" },
  { path: "/server-status", what: "Apache status page", confirm: /Apache Server Status|Total Accesses/i, severity: "medium" },
  { path: "/actuator/env", what: "Spring Boot environment endpoint", confirm: /propertySources|systemEnvironment/, severity: "critical" },
  { path: "/debug/pprof/", what: "Go profiling endpoint", confirm: /pprof|goroutine/i, severity: "high" },
  { path: "/phpinfo.php", what: "PHP configuration page", confirm: /phpinfo\(\)|PHP Version/i, severity: "high" },
  { path: "/.DS_Store", what: "directory listing artifact", confirm: /Bud1/, severity: "medium" },
  { path: "/swagger.json", what: "API specification", confirm: /"swagger"|"openapi"/, severity: "medium" },
];

const HEADER_CHECKS: { header: string; label: string; why: string }[] = [
  {
    header: "x-content-type-options",
    label: "X-Content-Type-Options",
    why: "Without it, browsers may guess a response's type and execute a file that was meant to be a download.",
  },
  {
    header: "x-frame-options",
    label: "X-Frame-Options or CSP frame-ancestors",
    why: "Without it, your pages can be loaded invisibly inside an attacker's page and clicks can be hijacked.",
  },
  {
    header: "referrer-policy",
    label: "Referrer-Policy",
    why: "Without it, full URLs including any tokens in them are sent to third-party sites your pages link to.",
  },
];

function collectDomains(ctx: ScanContext): string[] {
  const raw = process.env.GUARDIAN_UNIT_DOMAINS ?? "";
  return raw
    .split(/[,\s]+/)
    .map((d) => d.trim())
    .filter(Boolean)
    .map((d) => (/^https?:\/\//i.test(d) ? d : `https://${d}`));
}

async function get(
  url: string,
  signal: AbortSignal,
  method: "GET" | "HEAD" = "GET",
): Promise<{ status: number; headers: Headers; body: string } | null> {
  try {
    const res = await fetch(url, {
      method,
      redirect: "manual",
      headers: { "user-agent": "Guardian Unit/0.1 (local security scan; +https://github.com/)" },
      signal: AbortSignal.any([signal, AbortSignal.timeout(12_000)]),
    });
    const body = method === "GET" ? (await res.text()).slice(0, 4096) : "";
    return { status: res.status, headers: res.headers, body };
  } catch {
    return null;
  }
}

export const surfaceScanner: Scanner = {
  name: "surface",
  title: "Public web surface",
  description:
    "Checks the domains you name for missing security headers and files that should never be public, such as .env or .git.",
  rules: RULES,
  requiresNetwork: true,

  appliesTo: (ctx) => collectDomains(ctx).length > 0,

  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const out: RawFinding[] = [];
    const domains = collectDomains(ctx);

    for (const origin of domains) {
      if (ctx.signal.aborted) break;
      ctx.progress(`checking ${origin}`);
      const host = new URL(origin).hostname;
      const target = { file: host, startLine: 1, endLine: 1 };

      const root = await get(origin, ctx.signal);
      if (!root) {
        out.push({
          ruleId: "SURF-MISSING-HEADERS",
          title: `${host} did not respond`,
          description: `Guardian Unit could not reach ${origin}. This is reported so the coverage statement stays honest: no checks ran against this host, which is not the same as it passing them.`,
          severity: "info",
          confidence: "confirmed",
          evidence: `no response from ${origin}`,
          exploit: "Not applicable. This is a coverage note, not a vulnerability.",
          remediation: {
            summary: "Confirm the hostname is correct and reachable from this machine.",
            steps: ["Check the spelling.", "Check whether a firewall or VPN is required to reach it from here."],
          },
          mappings: {},
          tags: ["surface", "coverage"],
          location: target,
        });
        continue;
      }

      const h = root.headers;

      // HSTS
      if (!h.get("strict-transport-security")) {
        out.push({
          ruleId: "SURF-NO-HSTS",
          title: `${host} does not send Strict-Transport-Security`,
          description: `${origin} responds without an HSTS header. HSTS tells the browser to refuse plain HTTP for this domain in future, which closes the window where a first request can be intercepted and downgraded.`,
          severity: "medium",
          confidence: "confirmed",
          evidence: `no strict-transport-security header on ${origin}`,
          exploit:
            "A user on a hostile network types your domain without a scheme. The browser tries HTTP first, the attacker intercepts that request and serves a proxied copy of your site over plain HTTP, capturing the login. HSTS makes the browser go straight to HTTPS and refuse to proceed if the certificate is wrong.",
          remediation: {
            summary: "Add Strict-Transport-Security with a long max-age.",
            steps: [
              "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains",
              "Start with a shorter max-age if you are unsure any subdomain lacks HTTPS, then raise it.",
              "Consider preload submission once you are confident every subdomain is HTTPS-only.",
            ],
          },
          mappings: { cwe: ["CWE-319"], owasp: ["A02:2021"], compliance: ["SOC2:CC6.7", "PCI-DSS-4.0:4.2.1"] },
          tags: ["surface", "headers"],
          location: target,
        });
      }

      // CSP
      const csp = h.get("content-security-policy");
      if (!csp) {
        out.push({
          ruleId: "SURF-NO-CSP",
          title: `${host} has no Content-Security-Policy`,
          description: `${origin} sends no Content-Security-Policy. CSP is what limits the blast radius of a cross-site scripting flaw: it tells the browser which script sources are legitimate, so injected script is refused even when the injection succeeds.`,
          severity: "medium",
          confidence: "confirmed",
          evidence: `no content-security-policy header on ${origin}`,
          exploit:
            "Any cross-site scripting flaw becomes fully exploitable: injected script runs, loads further payloads from anywhere, and posts stolen data to any destination. With a policy in place, most of those steps fail.",
          remediation: {
            summary: "Add a Content-Security-Policy, starting in report-only mode.",
            steps: [
              "Deploy with Content-Security-Policy-Report-Only first and collect violations for a week.",
              "Build the policy from what the reports show your site genuinely loads.",
              "Aim for script-src with nonces or hashes rather than 'unsafe-inline'.",
              "Switch to enforcing mode once reports are clean.",
            ],
          },
          mappings: { cwe: ["CWE-1021"], owasp: ["A05:2021"] },
          tags: ["surface", "headers"],
          location: target,
        });
      } else if (/unsafe-inline|unsafe-eval/.test(csp)) {
        out.push({
          ruleId: "SURF-WEAK-CSP",
          title: `${host} has a Content-Security-Policy that allows inline script`,
          description: `${origin} sends a CSP containing ${/unsafe-inline/.test(csp) ? "'unsafe-inline'" : "'unsafe-eval'"}. The policy exists but permits the exact thing it is meant to prevent.`,
          severity: "low",
          confidence: "confirmed",
          evidence: `CSP on ${origin} contains ${/unsafe-inline/.test(csp) ? "unsafe-inline" : "unsafe-eval"}`,
          exploit:
            "Injected inline script executes normally, so the policy provides almost no protection for the case it was added to address.",
          remediation: {
            summary: "Replace unsafe-inline with per-request nonces or hashes.",
            steps: [
              "Generate a random nonce per response and mark legitimate inline scripts with it.",
              "Add 'strict-dynamic' so scripts loaded by trusted scripts are permitted without listing every host.",
              "Remove 'unsafe-eval' by eliminating dynamic code evaluation in the application.",
            ],
          },
          mappings: { cwe: ["CWE-1021"], owasp: ["A05:2021"] },
          tags: ["surface", "headers"],
          location: target,
        });
      }

      // Common headers
      for (const check of HEADER_CHECKS) {
        const present =
          h.get(check.header) ||
          (check.header === "x-frame-options" && csp && /frame-ancestors/.test(csp));
        if (present) continue;
        out.push({
          ruleId: "SURF-MISSING-HEADERS",
          title: `${host} is missing ${check.label}`,
          description: `${origin} does not send ${check.label}. ${check.why}`,
          severity: "low",
          confidence: "confirmed",
          evidence: `no ${check.header} header on ${origin}`,
          exploit: check.why,
          remediation: {
            summary: `Add the ${check.label} response header at your edge or in your framework.`,
            steps: [
              check.header === "x-content-type-options"
                ? "Send: X-Content-Type-Options: nosniff"
                : check.header === "x-frame-options"
                  ? "Send: X-Frame-Options: DENY, or add frame-ancestors 'none' to your CSP."
                  : "Send: Referrer-Policy: strict-origin-when-cross-origin",
              "Set it once at the CDN or reverse proxy so every response is covered.",
            ],
          },
          mappings: { cwe: ["CWE-1021", "CWE-693"], owasp: ["A05:2021"] },
          tags: ["surface", "headers"],
          location: target,
        });
      }

      // Server banner
      const server = h.get("server") ?? h.get("x-powered-by");
      if (server && /\d+\.\d+/.test(server)) {
        out.push({
          ruleId: "SURF-SERVER-BANNER",
          title: `${host} advertises its software version`,
          description: `${origin} returns "${server}" in its response headers. Version numbers let an attacker skip reconnaissance and go directly to exploits known to affect that exact build.`,
          severity: "info",
          confidence: "confirmed",
          evidence: `server banner "${server}" on ${origin}`,
          exploit:
            "Attackers index the internet by banner. When a vulnerability is published for a specific version, everything advertising it is targeted within hours, before most operators have patched.",
          remediation: {
            summary: "Suppress the version in the banner.",
            steps: [
              "nginx: server_tokens off;  Apache: ServerTokens Prod and ServerSignature Off.",
              "Express: app.disable('x-powered-by').",
              "This is defence in depth, not a fix. Keep patching.",
            ],
          },
          mappings: { cwe: ["CWE-200"], owasp: ["A05:2021"] },
          tags: ["surface", "headers", "information-disclosure"],
          location: target,
        });
      }

      // Permissive CORS
      const acao = h.get("access-control-allow-origin");
      const acac = h.get("access-control-allow-credentials");
      if (acao === "*" && acac === "true") {
        out.push({
          ruleId: "SURF-CORS-PERMISSIVE",
          title: `${host} allows any origin with credentials`,
          description: `${origin} returns Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.`,
          severity: "high",
          confidence: "confirmed",
          evidence: `ACAO: * with ACAC: true on ${origin}`,
          exploit:
            "A logged-in user visits any attacker page. That page reads authenticated responses from your API using the victim's session and sends the data onward.",
          remediation: {
            summary: "Reflect only origins from an explicit allow-list, and add Vary: Origin.",
            steps: [
              "Maintain an allow-list of origins that genuinely need credentialed access.",
              "Echo the request origin only when it is on the list.",
              "Add Vary: Origin so caches do not serve one origin's response to another.",
            ],
          },
          mappings: { cwe: ["CWE-942"], owasp: ["A05:2021"] },
          tags: ["surface", "cors"],
          location: target,
        });
      }

      // HTTP to HTTPS redirect
      const plain = await get(origin.replace(/^https:/, "http:"), ctx.signal, "HEAD");
      if (plain && plain.status >= 200 && plain.status < 300) {
        out.push({
          ruleId: "SURF-NO-HTTPS-REDIRECT",
          title: `${host} serves content over plain HTTP`,
          description: `A request to http://${host} returned ${plain.status} rather than redirecting to HTTPS. Anything sent over that connection travels unencrypted.`,
          severity: "high",
          confidence: "confirmed",
          evidence: `http://${host} returned ${plain.status} instead of a redirect`,
          exploit:
            "Anyone on the network path reads the traffic, including session cookies and credentials, and can modify responses to inject content. On public Wi-Fi this requires no special access.",
          remediation: {
            summary: "Redirect all HTTP traffic to HTTPS with a 301, then enable HSTS.",
            steps: [
              "Return 301 to the https:// equivalent for every HTTP request.",
              "Add HSTS so browsers stop trying HTTP at all.",
              "Check that health checks and webhooks still work after the change.",
            ],
          },
          mappings: { cwe: ["CWE-319"], owasp: ["A02:2021"], compliance: ["PCI-DSS-4.0:4.2.1"] },
          tags: ["surface", "tls"],
          location: target,
        });
      }

      // Sensitive paths
      for (const p of SENSITIVE_PATHS) {
        if (ctx.signal.aborted) break;
        const res = await get(new URL(p.path, origin).toString(), ctx.signal);
        if (!res || res.status !== 200) continue;
        if (!p.confirm.test(res.body)) continue;

        out.push({
          ruleId: "SURF-EXPOSED-PATH",
          title: `${host}${p.path} is publicly readable`,
          description: `A plain GET to ${origin}${p.path} returned a 200 with content matching a ${p.what}. This path should not be reachable from the internet.`,
          severity: p.severity,
          confidence: "high",
          evidence: `GET ${p.path} returned 200 with ${p.what} content`,
          exploit:
            p.path.startsWith("/.git")
              ? "The whole repository can be reconstructed from an exposed .git directory using freely available tooling, giving an attacker your complete source code and, usually, credentials from its history."
              : p.path === "/.env"
                ? "Environment files hold database URLs, API keys, and signing secrets. This is a direct handover of the application's credentials with no exploitation required."
                : "The contents disclose internal configuration that shortens the path to a working attack, and frequently include credentials outright.",
          remediation: {
            summary: `Stop serving ${p.path} and rotate anything it disclosed.`,
            steps: [
              `Block ${p.path} at your web server, reverse proxy, or CDN.`,
              "Move the file outside the document root. Blocking a path while the file remains reachable by another route is not a fix.",
              "Rotate every credential the file contains. Assume it was read.",
              "Check access logs to see how long it has been exposed and who fetched it.",
            ],
            outOfBandAction:
              "Rotate every credential this path disclosed. Public exposure means compromise until proven otherwise.",
          },
          mappings: { cwe: ["CWE-200", "CWE-538"], owasp: ["A01:2021", "A05:2021"] },
          tags: ["surface", "exposure"],
          location: target,
        });
      }
    }

    return out;
  },
};
