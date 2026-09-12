import type { RawFinding, RuleDoc, ScanContext, Scanner } from "../core/types.ts";
import {
  inComment,
  inRegexLiteral,
  isClientReachable,
  isServerOnly,
  isTestFile,
  lineOf,
  matches,
  safeLang,
} from "./_shared.ts";
import { safeSnippet } from "../core/redact.ts";

/**
 * AI-generated code failure patterns.
 *
 * This scanner exists because assistant-written code fails in a small, highly
 * repeatable set of ways. The assistant optimizes for "the demo runs", and the
 * shortcuts it takes to get there are the same ones every time: turn off the
 * thing that was blocking the happy path, inline the key that made the example
 * work, trust the field the client can edit.
 *
 * Every rule here targets a pattern that a competent human would rarely write
 * but an assistant writes constantly. That is what makes them high-precision.
 */

const RULES: RuleDoc[] = [
  {
    id: "AIC-RLS-DISABLED",
    title: "Row-level security disabled on a table",
    severity: "critical",
    confidence: "high",
    threat: "Any client holding the public anon key can read or write the entire table.",
    mappings: { cwe: ["CWE-284", "CWE-732"], owasp: ["A01:2021"], compliance: ["SOC2:CC6.1", "GDPR:Art32"] },
  },
  {
    id: "AIC-RLS-PERMISSIVE",
    title: "Row-level security policy that allows everyone",
    severity: "critical",
    confidence: "high",
    threat: "A USING (true) policy means row-level security is enabled and enforcing nothing.",
    mappings: { cwe: ["CWE-284"], owasp: ["A01:2021"], compliance: ["SOC2:CC6.1"] },
  },
  {
    id: "AIC-PUBLIC-ENV-SECRET",
    title: "Secret-shaped variable behind a browser-exposed env prefix",
    severity: "critical",
    confidence: "high",
    threat: "The framework inlines this value into the client bundle at build time.",
    mappings: { cwe: ["CWE-200", "CWE-798"], owasp: ["A01:2021"], compliance: ["SOC2:CC6.1"] },
  },
  {
    id: "AIC-SERVICE-ROLE-CLIENT",
    title: "Privileged database key reachable from client code",
    severity: "critical",
    confidence: "high",
    threat: "The service_role key bypasses row-level security entirely. In a browser it is a full database takeover.",
    mappings: { cwe: ["CWE-798", "CWE-269"], owasp: ["A01:2021"], compliance: ["SOC2:CC6.1"] },
  },
  {
    id: "AIC-USER-METADATA-AUTHZ",
    title: "Authorization decision based on a client-editable field",
    severity: "critical",
    confidence: "high",
    threat: "A signed-in user can rewrite their own user_metadata through the auth API and grant themselves any role.",
    mappings: { cwe: ["CWE-639", "CWE-284"], owasp: ["A01:2021"], compliance: ["SOC2:CC6.3"] },
  },
  {
    id: "AIC-STORAGE-PUBLIC",
    title: "Object storage bucket left world-readable",
    severity: "high",
    confidence: "medium",
    threat: "Uploaded files, including other users' documents, are readable by anyone with the URL pattern.",
    mappings: { cwe: ["CWE-732"], owasp: ["A01:2021"], compliance: ["SOC2:CC6.1", "GDPR:Art32"] },
  },
  {
    id: "AIC-TLS-VERIFY-OFF",
    title: "TLS certificate verification disabled",
    severity: "high",
    confidence: "high",
    threat: "Any network attacker can intercept and modify this connection.",
    mappings: { cwe: ["CWE-295"], owasp: ["A02:2021"], compliance: ["PCI-DSS-4.0:4.2.1"] },
  },
  {
    id: "AIC-CORS-WILDCARD-CREDENTIALS",
    title: "Wildcard CORS combined with credentials",
    severity: "high",
    confidence: "high",
    threat: "Any website can make authenticated requests to this API using the visitor's session.",
    mappings: { cwe: ["CWE-942"], owasp: ["A05:2021"], compliance: ["SOC2:CC6.6"] },
  },
  {
    id: "AIC-AUTH-BYPASS-FLAG",
    title: "Authentication or authorization disabled by a flag",
    severity: "high",
    confidence: "medium",
    threat: "A development shortcut that reaches production removes access control entirely.",
    mappings: { cwe: ["CWE-489", "CWE-306"], owasp: ["A01:2021", "A05:2021"] },
  },
  {
    id: "AIC-UNPROTECTED-ROUTE",
    title: "Mutating API route with no visible authentication check",
    severity: "high",
    confidence: "low",
    threat: "An unauthenticated request can change or delete data.",
    mappings: { cwe: ["CWE-306"], owasp: ["A01:2021"], compliance: ["SOC2:CC6.1"] },
  },
  {
    id: "AIC-DANGEROUS-HTML",
    title: "Raw HTML injected into the DOM from a variable",
    severity: "high",
    confidence: "medium",
    threat: "Stored or reflected cross-site scripting, which steals sessions and performs actions as the victim.",
    mappings: { cwe: ["CWE-79"], owasp: ["A03:2021"] },
  },
  {
    id: "AIC-WEAK-CRYPTO",
    title: "Broken hash or cipher used for a security purpose",
    severity: "medium",
    confidence: "medium",
    threat: "MD5 and SHA-1 are collision-broken; ECB mode leaks plaintext structure.",
    mappings: { cwe: ["CWE-327", "CWE-328"], owasp: ["A02:2021"], compliance: ["PCI-DSS-4.0:4.2.1"] },
  },
  {
    id: "AIC-PASSWORD-FAST-HASH",
    title: "Password stored with a fast hash",
    severity: "critical",
    confidence: "high",
    threat: "A stolen database of SHA-256 passwords is cracked at billions of guesses per second.",
    mappings: { cwe: ["CWE-916"], owasp: ["A02:2021"], compliance: ["PCI-DSS-4.0:8.3.2", "SOC2:CC6.1"] },
  },
  {
    id: "AIC-DEBUG-PRODUCTION",
    title: "Debug mode or verbose errors enabled",
    severity: "medium",
    confidence: "medium",
    threat: "Stack traces disclose file paths, library versions, and query structure to attackers.",
    mappings: { cwe: ["CWE-489", "CWE-209"], owasp: ["A05:2021"] },
  },
];

/**
 * File types these rules apply to. Everything else -- markdown, text, RST,
 * notebooks -- is skipped outright, because prose about insecure code is not
 * insecure code.
 */
const SOURCE_FILE = /\.(?:ts|tsx|js|jsx|mjs|cjs|py|rb|go|php|java|kt|cs|sql|psql|vue|svelte|astro|tf|env|yml|yaml|json)$/i;

interface Check {
  ruleId: string;
  re: RegExp;
  files?: RegExp;
  title: (m: RegExpExecArray, file: string) => string;
  describe: (m: RegExpExecArray, file: string, line: number) => string;
  exploit: string;
  fix: { summary: string; steps: string[]; after?: string; outOfBand?: string };
  /** Return false to drop a match after looking at surrounding context. */
  guard?: (m: RegExpExecArray, text: string, file: string) => boolean;
  severityOverride?: (file: string, text: string) => RawFinding["severity"] | undefined;
}

const CHECKS: Check[] = [
  {
    ruleId: "AIC-RLS-DISABLED",
    files: /\.(sql|psql)$/i,
    re: /ALTER\s+TABLE\s+(?:(?:"?[\w.]+"?\.)?"?([\w]+)"?)\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY/gi,
    title: (m) => `Row-level security is switched off on "${m[1]}"`,
    describe: (m, file, line) =>
      `A migration in ${file} at line ${line} disables row-level security on the table "${m[1]}". In Supabase and any Postgres project that exposes tables through a public API, row-level security is the only thing standing between an anonymous request and the whole table. With it off, the table is readable and writable by anyone holding the public anon key, which by design is published in your frontend.`,
    exploit:
      "An attacker reads the anon key out of your JavaScript bundle, points a Supabase client at your project, and issues a select over the entire table. No authentication, no rate limit, no log entry that looks unusual. If the table also allows writes, they can modify or delete every row.",
    fix: {
      summary: `Re-enable row-level security on the table and write an explicit policy for each operation.`,
      steps: [
        "Re-enable it: ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;",
        "Add one policy per operation you intend to allow. A table with RLS enabled and no policies denies everything, which is the correct safe starting point.",
        "Scope each policy to the authenticated user, for example USING (auth.uid() = user_id).",
        "Verify by querying the table with the anon key and confirming you get zero rows.",
      ],
      after: "ALTER TABLE public.<table> ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY \"owners read own rows\"\n  ON public.<table> FOR SELECT\n  USING (auth.uid() = user_id);",
    },
  },
  {
    ruleId: "AIC-RLS-PERMISSIVE",
    files: /\.(sql|psql)$/i,
    re: /CREATE\s+POLICY\s+[^;]{0,200}?\s(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)/gi,
    title: () => "A row-level security policy allows every request",
    describe: (m, file, line) =>
      `${file} at line ${line} creates a policy whose condition is literally true. Row-level security reports as enabled, dashboards show a green check, and the policy permits every row to every caller. This is the most dangerous configuration of the three possible states, because it looks protected.`,
    exploit:
      "Identical to having no row-level security at all: anyone with the public anon key reads or writes every row. The difference is that your compliance checklist says row-level security is enabled, so nobody looks again.",
    fix: {
      summary: "Replace the true condition with a check against the authenticated user's identity.",
      steps: [
        "Decide who is genuinely allowed to see each row.",
        "Rewrite the policy to compare against auth.uid() or a server-side role claim.",
        "If a table really is public read-only reference data, keep USING (true) but restrict the policy to FOR SELECT and add a comment explaining the decision, so the next reader knows it was deliberate.",
      ],
      after: "DROP POLICY \"<name>\" ON public.<table>;\n\nCREATE POLICY \"<name>\"\n  ON public.<table> FOR SELECT\n  USING (auth.uid() = user_id);",
    },
  },
  {
    ruleId: "AIC-PUBLIC-ENV-SECRET",
    re: /\b((?:NEXT_PUBLIC|VITE|PUBLIC|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC|GATSBY|VUE_APP)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|SERVICE_KEY|PASSWORD|TOKEN|API_KEY|APIKEY|ACCESS_KEY|CLIENT_SECRET|WEBHOOK_SECRET|SIGNING|CREDENTIAL)[A-Z0-9_]*)\b/g,
    title: (m) => `${m[1]} is published to every visitor`,
    describe: (m, file, line) =>
      `${file} at line ${line} references ${m[1]}. Framework variables with this prefix are deliberately inlined into the JavaScript bundle at build time so that browser code can read them. The name of this variable says it holds a secret. Both things cannot be true safely.`,
    exploit:
      "The value is compiled into the JavaScript your site serves. An attacker loads your page, opens the network tab or searches the bundle for the variable name, and reads the credential. This requires no vulnerability and no access.",
    fix: {
      summary: "Rename the variable without the public prefix, move its use to server code, and rotate the value.",
      steps: [
        "Drop the public prefix from the variable name so the framework stops inlining it.",
        "Move every use of it into a server route, API handler, server action, or edge function.",
        "Rotate the credential at the provider. It has been served to every visitor since the first deploy that included it.",
        "Search your deployed bundle for the old variable name to confirm it is gone.",
      ],
      outOfBand: "Rotate the credential. It has been publicly served and must be treated as compromised.",
    },
  },
  {
    ruleId: "AIC-SERVICE-ROLE-CLIENT",
    re: /\b(SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SERVICE_KEY|service_role)\b/g,
    title: () => "The privileged database key is reachable from client code",
    describe: (m, file, line) =>
      `${file} at line ${line} references the Supabase service_role key. That key bypasses row-level security completely; it is the database's root credential. This file is client-reachable, which means the key is compiled into code that runs in a browser.`,
    exploit:
      "An attacker extracts the service_role key from the JavaScript bundle and gets unrestricted read and write access to every table in the project, ignoring every policy you wrote. This is a total database compromise reachable by viewing source.",
    fix: {
      summary: "Remove the service_role key from all client-reachable code and rotate it immediately.",
      steps: [
        "Move the operation into a server route, edge function, or backend service that the browser calls instead.",
        "In the browser, use only the anon key, and rely on row-level security to constrain what it can do.",
        "Rotate the service_role key in Supabase under Project Settings, API.",
        "Review your project's logs for queries that did not originate from your backend.",
      ],
      outOfBand: "Rotate the service_role key in the Supabase dashboard. Assume it is compromised.",
    },
    guard: (m, text, file) => isClientReachable(file, text) && !isServerOnly(file, text),
  },
  {
    ruleId: "AIC-USER-METADATA-AUTHZ",
    re: /\buser_metadata\s*(?:\?\.|\.|\[\s*['"])\s*(?:role|is_admin|isAdmin|admin|permissions?|plan|tier|subscription)\b/g,
    title: () => "Permission check reads a field the user controls",
    describe: (m, file, line) =>
      `${file} at line ${line} makes an authorization decision based on user_metadata. In Supabase Auth, user_metadata is writable by the signed-in user through the standard updateUser API. Anyone with an account can set their own role to whatever this code checks for.`,
    exploit:
      "An attacker signs up normally, then calls supabase.auth.updateUser({ data: { role: 'admin' } }) from the browser console. Their next request passes this check. They are now an administrator. The whole attack is one line of JavaScript and takes about ten seconds.",
    fix: {
      summary: "Move the role claim to app_metadata, which only the service role can write, and check it server-side.",
      steps: [
        "Store role and entitlement claims in app_metadata, not user_metadata. app_metadata cannot be written by the user.",
        "Set app_metadata from a trusted server context using the service_role key, or from a database trigger.",
        "Re-verify the claim on the server for every privileged operation. Never trust a claim decoded in the browser.",
        "Audit existing accounts for user_metadata role values that were self-assigned.",
      ],
      after: "// server-side\nconst { data: { user } } = await supabase.auth.getUser(jwt);\nif (user?.app_metadata?.role !== 'admin') {\n  return new Response('Forbidden', { status: 403 });\n}",
    },
  },
  {
    ruleId: "AIC-STORAGE-PUBLIC",
    re: /createBucket\s*\(\s*['"`][^'"`]+['"`]\s*,\s*\{[^}]*\bpublic\s*:\s*true|['"]public['"]\s*:\s*true[^}]{0,40}\bbucket|acl\s*[:=]\s*['"]public-read['"]|BlockPublicAcls\s*[:=]\s*(?:false|False)/g,
    title: () => "Object storage is readable by anyone",
    describe: (m, file, line) =>
      `${file} at line ${line} configures a storage bucket for public read access. Every object placed in it is retrievable by anyone who can guess or enumerate the URL, and object URLs are frequently predictable.`,
    exploit:
      "Attackers enumerate object paths, which are commonly sequential ids or user ids, and download other users' uploads: identity documents, invoices, medical records, private images. This is one of the most common sources of mass data exposure in consumer applications.",
    fix: {
      summary: "Make the bucket private and serve objects through short-lived signed URLs.",
      steps: [
        "Set the bucket to private.",
        "Generate signed URLs with a short expiry for each authorized download.",
        "Add a storage access policy that scopes objects to their owner.",
        "Audit what is already in the bucket. If personal data was exposed, breach-notification duties may apply.",
      ],
    },
  },
  {
    ruleId: "AIC-TLS-VERIFY-OFF",
    re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|ServerCertificateValidationCallback\s*(?:\+?=)|--insecure\b|\bcurl\b[^\n]*\s-k\b/g,
    title: () => "TLS certificate checking is turned off",
    describe: (m, file, line) =>
      `${file} at line ${line} disables TLS certificate verification. The connection is still encrypted, but the code no longer checks that it is talking to the right server, which is the part that makes encryption meaningful.`,
    exploit:
      "Anyone positioned on the network path, including on shared Wi-Fi, a compromised router, or a hostile cloud tenant, presents their own certificate. The client accepts it, and the attacker reads and rewrites every request and response, including credentials and API tokens.",
    fix: {
      summary: "Re-enable verification and fix the underlying certificate problem properly.",
      steps: [
        "Remove the flag that disables verification.",
        "If you hit a self-signed certificate in development, add that specific certificate to a trust store scoped to development only.",
        "If the certificate chain is genuinely broken, fix the chain on the server rather than ignoring it on the client.",
        "Confirm no build or deploy path sets NODE_TLS_REJECT_UNAUTHORIZED=0 globally.",
      ],
    },
  },
  {
    ruleId: "AIC-CORS-WILDCARD-CREDENTIALS",
    re: /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"][\s\S]{0,400}?Access-Control-Allow-Credentials['"]?\s*[,:]\s*['"]?true|origin\s*:\s*(?:['"]\*['"]|true)[\s\S]{0,200}?credentials\s*:\s*true|credentials\s*:\s*true[\s\S]{0,200}?origin\s*:\s*(?:['"]\*['"]|true)/g,
    title: () => "Any website can call this API with the visitor's credentials",
    describe: (m, file, line) =>
      `${file} at line ${line} allows every origin and also allows credentials. Browsers refuse this exact combination with a literal wildcard, so frameworks that implement it typically reflect the caller's origin back, which produces the same effect: every site is trusted.`,
    exploit:
      "A victim who is logged into your application visits any attacker-controlled page. That page issues authenticated requests to your API using the victim's cookies, reads the responses, and exfiltrates the data. The victim sees nothing.",
    fix: {
      summary: "Replace the wildcard with an explicit allow-list of origins you control.",
      steps: [
        "List the exact origins that legitimately need cross-origin access.",
        "Reflect an origin only after checking it against that list.",
        "Keep credentials enabled only for those origins.",
        "For public, unauthenticated endpoints, keep the wildcard but turn credentials off.",
      ],
      after: "const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com']);\nconst origin = req.headers.get('origin');\nif (origin && ALLOWED.has(origin)) {\n  res.setHeader('Access-Control-Allow-Origin', origin);\n  res.setHeader('Access-Control-Allow-Credentials', 'true');\n  res.setHeader('Vary', 'Origin');\n}",
    },
  },
  {
    ruleId: "AIC-AUTH-BYPASS-FLAG",
    re: /\b(?:SKIP_AUTH|DISABLE_AUTH|BYPASS_AUTH|NO_AUTH|AUTH_DISABLED|DISABLE_SECURITY|SKIP_VERIFICATION|ALLOW_ALL)\b\s*[:=]\s*(?:true|['"]true['"]|1|['"]1['"])|if\s*\(\s*(?:true|1)\s*\)\s*(?:\{[^}]{0,40})?\s*(?:return\s+(?:true|next\(\))|next\(\))/g,
    title: () => "Access control is switched off by a flag",
    describe: (m, file, line) =>
      `${file} at line ${line} contains a switch that disables authentication or authorization. These are almost always added to unblock local development and then forgotten. If the flag is readable from the environment, a misconfigured deploy turns it on in production.`,
    exploit:
      "If this flag is ever true in a deployed environment, every protected endpoint becomes public. Attackers routinely probe for exactly this by setting common bypass headers and environment-shaped parameters.",
    fix: {
      summary: "Remove the bypass, or make it structurally impossible to enable outside local development.",
      steps: [
        "Delete the flag if you can. A test suite should exercise real auth with test credentials rather than switching auth off.",
        "If it must exist, gate it on NODE_ENV === 'development' as a hard-coded constant, not on a runtime environment variable.",
        "Add a startup assertion that refuses to boot if the bypass is active and the environment is not development.",
      ],
    },
    guard: (m, text, file) => !isTestFile(file),
  },
  {
    ruleId: "AIC-DANGEROUS-HTML",
    re: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(?!['"`])([A-Za-z_$][\w$.?[\]'"()]*)/g,
    title: () => "Untrusted value written into the page as raw HTML",
    describe: (m, file, line) =>
      `${file} at line ${line} passes a variable straight into dangerouslySetInnerHTML. React's escaping, the thing that makes cross-site scripting rare in React apps, is switched off for this value.`,
    exploit:
      "If any part of that value can be influenced by a user, an attacker stores a script tag or an event handler in it. When another user loads the page, the script runs with that user's session and can read their data, act as them, or steal their token.",
    fix: {
      summary: "Render the value as text, or sanitize it with a maintained HTML sanitizer before injecting it.",
      steps: [
        "If the value does not need to be HTML, render it as a normal child so React escapes it.",
        "If it must be HTML, run it through a maintained sanitizer such as DOMPurify with a strict allow-list, and sanitize on the server as well as the client.",
        "Trace where the value comes from. If any path reaches user input, treat this as confirmed rather than potential.",
      ],
    },
  },
  {
    ruleId: "AIC-PASSWORD-FAST-HASH",
    re: /(?:createHash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"]\s*\)[\s\S]{0,120}?\b(?:password|passwd|pwd)\b)|(?:\b(?:password|passwd|pwd)\b[\s\S]{0,80}?createHash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"])|hashlib\.(?:md5|sha1|sha256)\s*\([^)]{0,60}password/gi,
    title: () => "Passwords hashed with a general-purpose hash",
    describe: (m, file, line) =>
      `${file} at line ${line} hashes what appears to be a password using a fast general-purpose hash. These functions are designed to be fast, which is the opposite of what password storage needs.`,
    exploit:
      "If the database is ever stolen, a commodity GPU tries billions of candidate passwords per second against SHA-256. Common and reused passwords fall in minutes. Because people reuse passwords, this compromises your users' accounts elsewhere too.",
    fix: {
      summary: "Use a purpose-built password hash: argon2id, scrypt, or bcrypt.",
      steps: [
        "Switch to argon2id where available, otherwise bcrypt with a cost factor of at least 12.",
        "Migrate existing hashes by rehashing on next successful login, keeping the old verification path until migration completes.",
        "Never implement your own salting or stretching scheme.",
      ],
      after: "import { hash, verify } from '@node-rs/argon2';\nconst stored = await hash(password);\nconst ok = await verify(stored, submitted);",
    },
  },
  {
    ruleId: "AIC-WEAK-CRYPTO",
    re: /createCipheriv\s*\(\s*['"][^'"]*-ecb['"]|createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|hashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-?1)['"]|DES\b|RC4\b/g,
    title: () => "Broken cryptographic primitive in use",
    describe: (m, file, line) =>
      `${file} at line ${line} uses a cryptographic primitive that is no longer considered safe. MD5 and SHA-1 have practical collision attacks, ECB mode reveals patterns in the plaintext, and DES and RC4 are broken outright.`,
    exploit:
      "Depends on use. For signatures or integrity checks, an attacker forges a colliding value. For ECB-mode encryption, structure in the plaintext is visible in the ciphertext without any key. For DES or RC4, the key space or the cipher itself is attackable directly.",
    fix: {
      summary: "Replace with SHA-256 for hashing and AES-256-GCM for encryption.",
      steps: [
        "For integrity or signing, use SHA-256 or better.",
        "For encryption, use AES-256-GCM with a unique nonce per message, or a library that picks for you such as libsodium.",
        "If the weak hash is used for a non-security purpose such as a cache key, keep it but add a comment saying so, so the next reader and the next scanner both understand the decision.",
      ],
    },
  },
  {
    ruleId: "AIC-DEBUG-PRODUCTION",
    re: /\bDEBUG\s*=\s*True\b|\bapp\.debug\s*=\s*True\b|\bapp\.run\s*\([^)]*debug\s*=\s*True|\bASPNETCORE_ENVIRONMENT\s*[:=]\s*['"]?Development|display_errors\s*=\s*On\b/g,
    title: () => "Debug mode is enabled",
    describe: (m, file, line) =>
      `${file} at line ${line} enables debug mode. In most frameworks this turns unhandled errors into full stack traces served to the requester, and in some, including Flask and Django, it exposes an interactive console.`,
    exploit:
      "An attacker triggers an error deliberately and reads back file paths, library versions, environment variables, and fragments of source. In Flask's debugger, if the PIN is bypassed or the console is unprotected, this is direct remote code execution.",
    fix: {
      summary: "Drive debug mode from the environment and make production default to off.",
      steps: [
        "Read the debug setting from an environment variable that defaults to off.",
        "Return generic error pages in production and log the detail server-side.",
        "Add a deployment check that fails if debug is enabled outside development.",
      ],
    },
    guard: (m, text, file) => !isTestFile(file),
  },
];

/**
 * Unprotected mutating route handlers. Structural rather than pattern-based:
 * find route handlers that mutate, then look for any authentication-shaped call
 * in the same function body. Reported at low confidence on purpose -- auth is
 * often applied by middleware this scanner cannot see -- so it is framed as a
 * question, not an accusation.
 */
const ROUTE_RE =
  /export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\s*\([\s\S]{0,3000}?\n\}/g;
const AUTH_HINT =
  /\b(?:getUser|getSession|auth\(\)|requireAuth|verifyToken|jwt\.verify|currentUser|getServerSession|isAuthenticated|authorize|withAuth|clerk|nextauth|checkPermission|can\(|ability)/i;

function scanRoutes(file: string, text: string): RawFinding[] {
  if (!/\/(?:api|app)\//.test(file) || !/route\.(?:ts|js|tsx|jsx)$/.test(file)) return [];
  const out: RawFinding[] = [];
  for (const m of matches(ROUTE_RE, text)) {
    const body = m[0];
    if (AUTH_HINT.test(body)) continue;
    const { line, text: lineText } = lineOf(text, m.index);
    out.push({
      ruleId: "AIC-UNPROTECTED-ROUTE",
      title: `${m[1]} handler in ${file} has no visible authentication check`,
      description:
        `The ${m[1]} handler in ${file} changes data but contains no call that looks like an authentication or authorization check. This may be fine if middleware protects the route. It is flagged at low confidence so you can confirm rather than assume, because a missing check on a mutating endpoint is one of the most commonly exploited flaws and one of the easiest to overlook.`,
      severity: "high",
      confidence: "low",
      evidence: `export async function ${m[1]}(...) in ${file} with no authentication-shaped call in the body`,
      exploit:
        `If no middleware protects this path, anyone on the internet can send a ${m[1]} request and change or delete data. Attackers find these by enumerating routes from the JavaScript bundle.`,
      remediation: {
        summary: "Confirm the route is protected, and if it is not, add an explicit check at the top of the handler.",
        steps: [
          "Check whether middleware covers this path. If it does, add a suppression with that reason so this stops being reported.",
          "If it does not, resolve the caller's identity at the start of the handler and return 401 when absent.",
          "Then check that the caller is allowed to act on this specific resource, not merely that they are logged in. Authentication is not authorization.",
        ],
        codeFix: {
          language: "typescript",
          after: "const { data: { user } } = await supabase.auth.getUser();\nif (!user) return new Response('Unauthorized', { status: 401 });\n\n// then check this user may act on THIS resource\nif (resource.ownerId !== user.id) {\n  return new Response('Forbidden', { status: 403 });\n}",
        },
      },
      mappings: { cwe: ["CWE-306", "CWE-862"], owasp: ["A01:2021"], compliance: ["SOC2:CC6.1"] },
      tags: ["ai-generated-code", "authorization", "needs-confirmation"],
      location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
    });
  }
  return out;
}

export const aiCodeScanner: Scanner = {
  name: "ai-code",
  title: "AI-generated code defects",
  description:
    "Finds the specific mistakes coding assistants make by default: access control switched off, privileged keys in browser code, permission checks on fields the user can edit.",
  rules: RULES,

  appliesTo: (ctx) =>
    ctx.files.some((f) => /\.(ts|tsx|js|jsx|mjs|cjs|py|sql|vue|svelte|astro|rb|go|php|java|cs)$/i.test(f)),

  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const out: RawFinding[] = [];
    let processed = 0;

    for (const file of ctx.files) {
      if (ctx.signal.aborted) break;
      if (++processed % 500 === 0) ctx.progress(`checked ${processed} files`);

      // Only real source and configuration files. Documentation is full of
      // deliberately insecure example code -- security guides, agent
      // definitions, tutorials -- and flagging a book chapter about SQL
      // injection as SQL injection is the fastest way to become noise.
      if (!SOURCE_FILE.test(file)) continue;

      const text = await ctx.read(file);
      if (!text) continue;

      out.push(...scanRoutes(file, text));

      for (const check of CHECKS) {
        if (check.files && !check.files.test(file)) continue;
        const seen = new Set<number>();
        for (const m of matches(check.re, text)) {
          if (inRegexLiteral(text, m.index) || inComment(text, m.index)) continue;
          if (check.guard && !check.guard(m, text, file)) continue;
          const { line, text: lineText } = lineOf(text, m.index);
          if (seen.has(line)) continue;
          seen.add(line);

          const rule = RULES.find((r) => r.id === check.ruleId)!;
          const severity =
            check.severityOverride?.(file, text) ??
            (isTestFile(file) && rule.severity === "critical" ? "medium" : rule.severity);

          out.push({
            ruleId: check.ruleId,
            title: check.title(m, file),
            description: check.describe(m, file, line),
            severity,
            confidence: rule.confidence,
            evidence: `${m[0].slice(0, 160)} at ${file}:${line}`,
            exploit: check.exploit,
            remediation: {
              summary: check.fix.summary,
              steps: check.fix.steps,
              codeFix: check.fix.after
                ? { language: safeLang(file), after: check.fix.after }
                : undefined,
              outOfBandAction: check.fix.outOfBand,
            },
            mappings: rule.mappings,
            tags: ["ai-generated-code", ...(isTestFile(file) ? ["test-context"] : [])],
            location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
          });
        }
      }
    }
    return out;
  },
};
