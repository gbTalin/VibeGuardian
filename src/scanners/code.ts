import type { RawFinding, RuleDoc, ScanContext, Scanner, Severity } from "../core/types.ts";
import {
  extname,
  inComment,
  inRegexLiteral,
  isTestFile,
  lineOf,
  matches,
  safeLang,
} from "./_shared.ts";
import { safeSnippet } from "../core/redact.ts";

/**
 * Application code vulnerabilities.
 *
 * Every rule in this file is written from scratch and licensed with the rest of
 * Guardian Unit. That is a deliberate legal position, not an accident: Semgrep's
 * community rules are published under a licence that permits internal use only
 * and forbids redistribution or offering them as a service, which makes them
 * unusable in a distributed commercial product. Vendoring them would be a
 * breach that surfaces during diligence.
 *
 * The detection style is taint-shaped rather than pure pattern matching: a
 * finding requires a source of untrusted input and a dangerous sink in a
 * plausible relationship, not merely the presence of a scary-looking function.
 * That is what separates "eval is used here" from "user input reaches eval".
 */

const RULES: RuleDoc[] = [
  {
    id: "CODE-SQL-INJECTION",
    title: "SQL query built by string concatenation with request data",
    severity: "critical",
    confidence: "medium",
    threat: "Attacker rewrites the query: reads any table, bypasses login, or destroys data.",
    mappings: { cwe: ["CWE-89"], owasp: ["A03:2021"], compliance: ["PCI-DSS-4.0:6.2.4", "SOC2:CC6.1"] },
  },
  {
    id: "CODE-COMMAND-INJECTION",
    title: "Shell command built from request data",
    severity: "critical",
    confidence: "medium",
    threat: "Remote code execution on the server.",
    mappings: { cwe: ["CWE-78"], owasp: ["A03:2021"] },
  },
  {
    id: "CODE-EVAL-USER-INPUT",
    title: "Request data passed to a code-evaluation function",
    severity: "critical",
    confidence: "medium",
    threat: "Remote code execution in the application runtime.",
    mappings: { cwe: ["CWE-94", "CWE-95"], owasp: ["A03:2021"] },
  },
  {
    id: "CODE-PATH-TRAVERSAL",
    title: "File path built from request data",
    severity: "high",
    confidence: "medium",
    threat: "Reads or writes files outside the intended directory, including credentials and source.",
    mappings: { cwe: ["CWE-22"], owasp: ["A01:2021"] },
  },
  {
    id: "CODE-SSRF",
    title: "Outbound request to a URL taken from request data",
    severity: "high",
    confidence: "medium",
    threat: "Server-side request forgery reaches internal services and cloud metadata endpoints.",
    mappings: { cwe: ["CWE-918"], owasp: ["A10:2021"] },
  },
  {
    id: "CODE-XSS-SINK",
    title: "Request data written into the page without escaping",
    severity: "high",
    confidence: "medium",
    threat: "Cross-site scripting: session theft and actions performed as the victim.",
    mappings: { cwe: ["CWE-79"], owasp: ["A03:2021"] },
  },
  {
    id: "CODE-DESERIALIZATION",
    title: "Untrusted data passed to an unsafe deserializer",
    severity: "critical",
    confidence: "high",
    threat: "Deserialization of attacker-controlled data is frequently direct remote code execution.",
    mappings: { cwe: ["CWE-502"], owasp: ["A08:2021"] },
  },
  {
    id: "CODE-OPEN-REDIRECT",
    title: "Redirect target taken from request data",
    severity: "medium",
    confidence: "medium",
    threat: "Phishing that begins on your legitimate domain and is therefore far more convincing.",
    mappings: { cwe: ["CWE-601"], owasp: ["A01:2021"] },
  },
  {
    id: "CODE-XXE",
    title: "XML parser configured to resolve external entities",
    severity: "high",
    confidence: "high",
    threat: "XML external entity processing reads local files and reaches internal network services.",
    mappings: { cwe: ["CWE-611"], owasp: ["A05:2021"] },
  },
  {
    id: "CODE-INSECURE-RANDOM",
    title: "Non-cryptographic randomness used for a security value",
    severity: "medium",
    confidence: "medium",
    threat: "Predictable tokens, session identifiers, or password-reset links.",
    mappings: { cwe: ["CWE-338", "CWE-330"], owasp: ["A02:2021"] },
  },
  {
    id: "CODE-COOKIE-INSECURE",
    title: "Session cookie missing HttpOnly, Secure, or SameSite",
    severity: "medium",
    confidence: "high",
    threat: "Session theft through cross-site scripting or network interception.",
    mappings: { cwe: ["CWE-1004", "CWE-614"], owasp: ["A05:2021"], compliance: ["SOC2:CC6.6"] },
  },
  {
    id: "CODE-TIMING-COMPARISON",
    title: "Secret compared with a non-constant-time operator",
    severity: "low",
    confidence: "medium",
    threat: "Timing side channel that can leak a token or signature byte by byte.",
    mappings: { cwe: ["CWE-208"], owasp: ["A02:2021"] },
  },
];

/** Untrusted input, per language family. */
const SOURCES: Record<string, RegExp> = {
  js: /\breq(?:uest)?\.(?:body|query|params|cookies|headers)\b|\bawait\s+req(?:uest)?\.(?:json|text|formData)\(\)|\bsearchParams\.get\(|\bctx\.(?:query|params|request)\b|\bevent\.(?:body|queryStringParameters|pathParameters)\b|\bprocess\.argv\b|\bwindow\.location\b|\bdocument\.(?:URL|location|referrer)\b|\blocation\.(?:hash|search|href)\b/,
  py: /\brequest\.(?:args|form|json|values|data|files|cookies|headers|GET|POST)\b|\bflask\.request\b|\bsys\.argv\b|\binput\s*\(/,
  rb: /\bparams\[|\brequest\.(?:params|body|query_parameters|headers)\b/,
  php: /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/,
  go: /\br\.(?:URL\.Query\(\)|FormValue|PostFormValue|Header\.Get|Body)\b|\bmux\.Vars\(/,
  java: /\brequest\.get(?:Parameter|Header|QueryString|InputStream)\s*\(|@RequestParam|@PathVariable|@RequestBody/,
  cs: /\bRequest\.(?:Query|Form|Headers|Cookies|Body)\b|\[FromQuery\]|\[FromBody\]|\[FromRoute\]/,
};

function familyOf(file: string): keyof typeof SOURCES | null {
  const e = extname(file);
  if ([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"].includes(e)) return "js";
  if (e === ".py") return "py";
  if (e === ".rb") return "rb";
  if (e === ".php") return "php";
  if (e === ".go") return "go";
  if ([".java", ".kt"].includes(e)) return "java";
  if (e === ".cs") return "cs";
  return null;
}

interface SinkRule {
  ruleId: string;
  /** Sink patterns keyed by language family; a family absent here is not checked. */
  sinks: Partial<Record<keyof typeof SOURCES, RegExp>>;
  /** Require a source within this many characters of the sink. Set 0 to skip the taint requirement. */
  proximity: number;
  /** Require interpolation or concatenation in the sink's argument. */
  requireDynamic?: boolean;
  severity?: Severity;
  title: string;
  describe: (file: string, line: number) => string;
  exploit: string;
  steps: string[];
  fix?: string;
}

const SINKS: SinkRule[] = [
  {
    ruleId: "CODE-SQL-INJECTION",
    sinks: {
      js: /\b(?:query|execute|raw|exec)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,200}?['"]\s*\+)/gi,
      py: /\b(?:execute|executemany|raw|cursor\.execute)\s*\(\s*(?:f['"]|['"][^'"]*['"]\s*%|['"][^'"]*['"]\s*\+|['"][^'"]*\{)/gi,
      php: /\b(?:mysqli_query|mysql_query|->query|->exec)\s*\(\s*['"][^'"]*\$/gi,
      rb: /\.(?:find_by_sql|where|execute)\s*\(\s*["'][^"']*#\{/gi,
      java: /\b(?:createQuery|createNativeQuery|executeQuery|executeUpdate)\s*\(\s*["'][^"']*["']\s*\+/gi,
      cs: /new\s+Sql(?:Command|DataAdapter)\s*\(\s*[$@]?["'][^"']*(?:\{|\+)/gi,
      go: /\b(?:Query|Exec|QueryRow)\s*\(\s*(?:fmt\.Sprintf|["'][^"']*["']\s*\+)/gi,
    },
    proximity: 900,
    title: "SQL query assembled from untrusted input",
    describe: (file, line) =>
      `${file} at line ${line} builds a SQL statement by concatenating or interpolating values, and request-shaped input appears nearby. When user input becomes part of the query text rather than a parameter, the user is writing SQL.`,
    exploit:
      "An attacker supplies a value like ' OR 1=1 -- and changes what the query means. Depending on the statement, that reads every row in the table, bypasses an authentication check, or, with a stacked statement, drops the table. Automated tooling finds and exploits these without human involvement.",
    steps: [
      "Use parameterized queries. Pass the value as a parameter so the database treats it as data, never as SQL.",
      "If a table or column name must be dynamic, validate it against a hard-coded allow-list. Identifiers cannot be parameterized.",
      "An ORM's query builder is safe; its raw-SQL escape hatch is not. Check which one this is.",
      "Give the application's database user only the privileges it needs, so a successful injection is contained.",
    ],
    fix: "// unsafe\nconst rows = await db.query(`SELECT * FROM users WHERE email = '${email}'`);\n\n// safe: the value is a parameter, not part of the statement\nconst rows = await db.query('SELECT * FROM users WHERE email = $1', [email]);",
  },
  {
    ruleId: "CODE-COMMAND-INJECTION",
    sinks: {
      js: /\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/g,
      py: /\b(?:os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen))\s*\(\s*(?:f['"]|['"][^'"]*['"]\s*[%+]|['"][^'"]*\{)/g,
      php: /\b(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*['"]?[^'")]*\$/g,
      rb: /(?:`[^`]*#\{|system\s*\(\s*["'][^"']*#\{|%x\([^)]*#\{)/g,
      java: /\bRuntime\.getRuntime\(\)\.exec\s*\(\s*["'][^"']*["']\s*\+|\bProcessBuilder\s*\(\s*["'][^"']*["']\s*\+/g,
      go: /\bexec\.Command\s*\(\s*(?:"[^"]*",\s*)?fmt\.Sprintf/g,
      cs: /\bProcess\.Start\s*\(\s*[$@]?["'][^"']*\{/g,
    },
    proximity: 900,
    title: "Shell command assembled from untrusted input",
    describe: (file, line) =>
      `${file} at line ${line} builds a command string with interpolated values and executes it, with request-shaped input nearby. Shell metacharacters in that input are interpreted by the shell, not treated as text.`,
    exploit:
      "An attacker supplies a value containing a semicolon or backtick and appends their own command. It runs on your server with the application's privileges: read the environment including every secret, open a reverse shell, or pivot into your internal network. This is one of the most severe outcomes possible in a web application.",
    steps: [
      "Pass arguments as an array rather than building a command string. execFile, spawn with an argument list, and subprocess.run with a list all avoid the shell entirely.",
      "Never enable shell: true with any interpolated value.",
      "If the input selects an operation, map it through a fixed allow-list rather than passing it through.",
      "Validate against a strict pattern when a value must be passed, and reject rather than sanitize.",
    ],
    fix: "// unsafe: the shell parses the whole string\nexec(`convert ${filename} out.png`);\n\n// safe: arguments are passed directly, no shell involved\nexecFile('convert', [filename, 'out.png']);",
  },
  {
    ruleId: "CODE-EVAL-USER-INPUT",
    sinks: {
      js: /\b(?:eval|Function|setTimeout|setInterval)\s*\(\s*(?!function|\(\s*\)|\s*\(\s*\)\s*=>)(?:[A-Za-z_$][\w$.]*|`[^`]*\$\{)/g,
      py: /\b(?:eval|exec|compile)\s*\(\s*(?!['"])[A-Za-z_][\w.]*/g,
      php: /\b(?:eval|assert|create_function|preg_replace)\s*\(\s*['"]?[^'")]*\$/g,
      rb: /\b(?:eval|instance_eval|class_eval|send)\s*\(\s*[a-z_][\w]*/g,
    },
    proximity: 800,
    title: "Untrusted input reaches a code-evaluation function",
    describe: (file, line) =>
      `${file} at line ${line} passes a variable to a function that evaluates its argument as code, and request-shaped input appears nearby.`,
    exploit:
      "Whatever the attacker supplies becomes code running in your application's process, with its memory, its environment variables, and its database connections. There is no partial version of this outcome.",
    steps: [
      "Remove the evaluation. There is almost always a direct way to express the intent.",
      "For dynamic dispatch, use an explicit object mapping names to functions and reject anything not in it.",
      "For parsing data, use a real parser: JSON.parse for JSON, a schema validator for structured input.",
      "Pass a function reference to setTimeout and setInterval, never a string.",
    ],
    fix: "// unsafe\nconst result = eval(userExpression);\n\n// safe: a fixed set of permitted operations\nconst OPS = { add: (a, b) => a + b, mul: (a, b) => a * b };\nconst op = OPS[userChoice];\nif (!op) throw new Error('unsupported operation');\nconst result = op(a, b);",
  },
  {
    ruleId: "CODE-PATH-TRAVERSAL",
    sinks: {
      js: /\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|sendFile)\s*\(\s*(?:`[^`]*\$\{|(?:path\.)?join\s*\([^)]*(?:req|param|quer|input|name|file))/gi,
      py: /\bopen\s*\(\s*(?:f['"]|os\.path\.join\s*\([^)]*request|['"][^'"]*['"]\s*[+%])/g,
      php: /\b(?:file_get_contents|fopen|include|require|readfile|unlink)\s*\(\s*['"]?[^'")]*\$_(?:GET|POST|REQUEST)/g,
      java: /new\s+File(?:InputStream|OutputStream)?\s*\(\s*[^)]*(?:request\.getParameter|\+)/g,
    },
    proximity: 700,
    title: "File path built from untrusted input",
    describe: (file, line) =>
      `${file} at line ${line} opens a file whose path incorporates a variable, with request-shaped input nearby. Path separators and parent references in that input change which file is opened.`,
    exploit:
      "An attacker requests ../../../../etc/passwd, or on your own service ../../.env, and reads files outside the intended directory: environment files with database credentials, private keys, application source. If the path reaches a write operation, they overwrite files instead.",
    steps: [
      "Resolve the final path and verify it is still inside the intended directory before opening it.",
      "Strip directory components from user-supplied names rather than trying to filter dangerous sequences; blocklists for traversal are consistently bypassed.",
      "Where possible, do not use user input as a path at all. Store an identifier, look up the real path from your database.",
    ],
    fix: "import { resolve, relative } from 'node:path';\n\nconst ROOT = resolve('/srv/uploads');\nconst target = resolve(ROOT, userSuppliedName);\nconst rel = relative(ROOT, target);\nif (rel.startsWith('..') || rel === '') {\n  throw new Error('path outside upload directory');\n}\nawait readFile(target);",
  },
  {
    ruleId: "CODE-SSRF",
    sinks: {
      js: /\b(?:fetch|axios(?:\.(?:get|post|put|delete))?|got|request|http\.get|https\.get)\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_$][\w$.]*\s*(?:\)|,))/g,
      py: /\b(?:requests\.(?:get|post|put|delete)|urlopen|httpx\.(?:get|post))\s*\(\s*(?!['"])[A-Za-z_][\w.]*/g,
      go: /\bhttp\.(?:Get|Post)\s*\(\s*(?!")[A-Za-z_][\w.]*/g,
      php: /\b(?:file_get_contents|curl_setopt)\s*\([^)]*\$_(?:GET|POST|REQUEST)/g,
    },
    proximity: 600,
    requireDynamic: true,
    severity: "high",
    title: "Outbound request to a URL from untrusted input",
    describe: (file, line) =>
      `${file} at line ${line} makes an HTTP request to a URL held in a variable, with request-shaped input nearby. Your server will fetch whatever address the caller names, from inside your network.`,
    exploit:
      "The attacker supplies an internal address. Your server reaches places they cannot: the cloud metadata endpoint at 169.254.169.254, which on a misconfigured instance returns temporary IAM credentials; internal admin panels; databases bound to localhost. The response often comes back to them in your reply.",
    steps: [
      "Validate the URL against an allow-list of permitted hosts before fetching.",
      "Reject private and link-local address ranges after DNS resolution, not before, so a hostname that resolves to an internal address is caught.",
      "Disable redirect following, or re-validate the target on each redirect.",
      "Require IMDSv2 on cloud instances so a simple GET cannot retrieve credentials.",
      "Where feasible, route outbound fetches through a proxy that enforces the allow-list independently of application code.",
    ],
    fix: "const ALLOWED_HOSTS = new Set(['api.partner.com', 'cdn.example.com']);\n\nconst url = new URL(userUrl);\nif (url.protocol !== 'https:' || !ALLOWED_HOSTS.has(url.hostname)) {\n  throw new Error('destination not permitted');\n}\nconst { address } = await dns.promises.lookup(url.hostname);\nif (isPrivateAddress(address)) throw new Error('internal address blocked');\nawait fetch(url, { redirect: 'error' });",
  },
  {
    ruleId: "CODE-DESERIALIZATION",
    sinks: {
      py: /\b(?:pickle|cPickle|dill|shelve)\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?(?:Safe|C?Safe)Loader)/g,
      php: /\bunserialize\s*\(\s*[^)]*\$_(?:GET|POST|REQUEST|COOKIE)/g,
      java: /new\s+ObjectInputStream\s*\([^)]*\)\s*\.readObject\s*\(|XMLDecoder\s*\(/g,
      rb: /\b(?:Marshal\.load|YAML\.load)\s*\((?!.*safe)/g,
      cs: /new\s+BinaryFormatter\s*\(\)|JavaScriptSerializer|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Objects|Auto)/g,
    },
    proximity: 0,
    severity: "critical",
    title: "Unsafe deserializer in use",
    describe: (file, line) =>
      `${file} at line ${line} uses a deserializer that reconstructs arbitrary object types from its input. These formats are not data formats; they are instructions for building objects, and building an object can run code.`,
    exploit:
      "An attacker crafts a serialized payload that, during reconstruction, invokes methods already present in your application's dependencies, chained to reach command execution. Ready-made gadget chains exist for common Python, Java, PHP, and .NET dependency sets, so this rarely requires original work.",
    steps: [
      "Use a data-only format. JSON with schema validation cannot instantiate objects.",
      "For YAML, use the safe loader: yaml.safe_load in Python, YAML.safe_load in Ruby.",
      "Never deserialize pickle, Marshal, BinaryFormatter, or Java serialization from any source you do not fully control.",
      "If the format cannot change, sign the payload and verify the signature before deserializing.",
    ],
    fix: "# unsafe: reconstructs arbitrary objects\ndata = pickle.loads(request.data)\n\n# safe: data only\nimport json\ndata = json.loads(request.data)\nvalidate_against_schema(data)",
  },
  {
    ruleId: "CODE-XXE",
    sinks: {
      py: /etree\.(?:parse|fromstring)\s*\(|xml\.dom\.minidom\.parse|xmlrpc\.client/g,
      java: /DocumentBuilderFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,400}setFeature)|SAXParserFactory\.newInstance\s*\(\s*\)(?![\s\S]{0,400}setFeature)/g,
      php: /\blibxml_disable_entity_loader\s*\(\s*false\s*\)|LIBXML_NOENT/g,
      cs: /XmlReaderSettings\s*\{[^}]*DtdProcessing\s*=\s*DtdProcessing\.Parse|new\s+XmlDocument\s*\(\s*\)(?![\s\S]{0,300}XmlResolver\s*=\s*null)/g,
    },
    proximity: 0,
    severity: "high",
    title: "XML parser may resolve external entities",
    describe: (file, line) =>
      `${file} at line ${line} parses XML without visibly disabling external entity resolution. A default-configured XML parser will fetch and inline whatever an entity declaration points at.`,
    exploit:
      "The attacker submits XML declaring an entity that points at file:///etc/passwd or at an internal HTTP endpoint. The parser fetches it and includes the content in the parsed document, which is frequently echoed back. This gives both local file disclosure and server-side request forgery from one payload.",
    steps: [
      "Disable DTD processing and external entity resolution on the parser explicitly.",
      "In Python, use defusedxml as a drop-in replacement.",
      "In Java, set the disallow-doctype-decl feature to true on the factory.",
      "In .NET, set XmlResolver to null and DtdProcessing to Prohibit.",
      "If you control the format, prefer JSON.",
    ],
  },
  {
    ruleId: "CODE-XSS-SINK",
    sinks: {
      js: /\b(?:innerHTML|outerHTML)\s*=\s*(?!['"`]\s*['"`])[A-Za-z_$`]|\bdocument\.write(?:ln)?\s*\(|\binsertAdjacentHTML\s*\(\s*['"][^'"]+['"]\s*,\s*(?!['"])/g,
      php: /\becho\s+\$_(?:GET|POST|REQUEST)|\bprint\s+\$_(?:GET|POST|REQUEST)/g,
    },
    proximity: 700,
    severity: "high",
    title: "Untrusted value written to the page as HTML",
    describe: (file, line) =>
      `${file} at line ${line} assigns a variable into the document as raw HTML, with untrusted input nearby. The browser parses the value as markup, so any tags or event handlers in it become live.`,
    exploit:
      "An attacker stores a payload such as an img tag with an onerror handler. Every user who views the affected page runs it, in their own session. The script reads their token, performs actions as them, or rewrites the page to capture their password.",
    steps: [
      "Use textContent instead of innerHTML when the value is text, which is nearly always.",
      "If HTML is genuinely required, sanitize with a maintained library such as DOMPurify using a strict allow-list.",
      "Sanitize on the server as well; client-side sanitization alone is bypassed by anything that does not go through your page.",
      "Add a Content Security Policy so an injected inline script does not execute even if one gets through.",
    ],
    fix: "// unsafe\nel.innerHTML = userComment;\n\n// safe: the browser never parses this as markup\nel.textContent = userComment;",
  },
  {
    ruleId: "CODE-OPEN-REDIRECT",
    sinks: {
      js: /\b(?:res\.redirect|window\.location(?:\.href)?\s*=|location\.replace\s*\()\s*(?:`[^`]*\$\{|[A-Za-z_$][\w$.]*\s*\)?)/g,
      py: /\bredirect\s*\(\s*(?!['"])[A-Za-z_][\w.]*/g,
      php: /\bheader\s*\(\s*['"]Location:\s*['"]\s*\.\s*\$/g,
    },
    proximity: 500,
    severity: "medium",
    title: "Redirect destination taken from untrusted input",
    describe: (file, line) =>
      `${file} at line ${line} redirects to a destination held in a variable, with request-shaped input nearby. The caller chooses where your application sends the user.`,
    exploit:
      "An attacker sends a link that starts on your real domain and redirects to a lookalike login page. The victim checks the domain, sees yours, and trusts it. This is a standard component of credential-phishing campaigns because it defeats the one check users are trained to perform.",
    steps: [
      "Redirect only to paths, never to full URLs, by stripping the scheme and host.",
      "If external redirects are required, validate against an allow-list of destinations.",
      "Reject protocol-relative URLs beginning with // , which many naive checks miss.",
    ],
    fix: "// safe: force the destination to be a path on this origin\nconst target = new URL(userTarget, 'https://app.example.com');\nif (target.origin !== 'https://app.example.com') {\n  return res.redirect('/');\n}\nreturn res.redirect(target.pathname + target.search);",
  },
];

/** Checks that need no taint source. */
const STANDALONE: {
  ruleId: string;
  re: RegExp;
  files: RegExp;
  severity: Severity;
  title: string;
  describe: (file: string, line: number, m: RegExpExecArray) => string;
  exploit: string;
  steps: string[];
  fix?: string;
}[] = [
  {
    ruleId: "CODE-INSECURE-RANDOM",
    files: /\.(js|jsx|ts|tsx|mjs|py|rb|java|go|php)$/i,
    re: /Math\.random\s*\(\s*\)[\s\S]{0,120}?(?:token|secret|password|key|otp|nonce|salt|session|reset|verif|invite|code)|(?:token|secret|password|key|otp|nonce|salt|session|reset|verif|invite|code)[\s\S]{0,120}?Math\.random\s*\(\s*\)|\brandom\.(?:random|randint|choice)\s*\([^)]*\)[\s\S]{0,80}?(?:token|secret|password|otp)/gi,
    severity: "medium",
    title: "Security value generated with a predictable random source",
    describe: (file, line) =>
      `${file} at line ${line} generates what looks like a security-relevant value using a general-purpose random function. These generators are fast and statistically uniform but entirely predictable: given a few outputs, the internal state and every future output can be reconstructed.`,
    exploit:
      "An attacker requests several tokens, recovers the generator state, and predicts the next values. That means forging password-reset links for other accounts, guessing session identifiers, or predicting one-time codes. There is no brute force involved.",
    steps: [
      "Use a cryptographic generator: crypto.randomBytes or crypto.randomUUID in Node, secrets in Python, SecureRandom in Java and Ruby.",
      "Use at least 128 bits of entropy for anything acting as a credential.",
      "Invalidate any tokens already issued by the weak generator.",
    ],
    fix: "// unsafe\nconst token = Math.random().toString(36).slice(2);\n\n// safe\nimport { randomBytes } from 'node:crypto';\nconst token = randomBytes(32).toString('base64url');",
  },
  {
    ruleId: "CODE-COOKIE-INSECURE",
    files: /\.(js|jsx|ts|tsx|mjs|py|rb|go|php|java|cs)$/i,
    re: /(?:res\.cookie|setCookie|set_cookie|Set-Cookie|cookies\.set)\s*\([\s\S]{0,220}?\)/g,
    severity: "medium",
    title: "Cookie set without full protection flags",
    describe: (file, line) =>
      `${file} at line ${line} sets a cookie that is missing one or more of httpOnly, secure, and sameSite. Each of those closes a different attack path, and a session cookie needs all three.`,
    exploit:
      "Without httpOnly, any cross-site scripting flaw anywhere on the domain reads the session token directly from JavaScript. Without secure, the cookie is sent over plain HTTP and can be captured on the network. Without sameSite, another site can trigger authenticated requests from the victim's browser.",
    steps: [
      "Set httpOnly: true so JavaScript cannot read the cookie.",
      "Set secure: true so it is only sent over HTTPS.",
      "Set sameSite to 'lax' or 'strict'. Use 'none' only with secure and only when a genuine cross-site flow requires it.",
      "Scope the path and set a sensible expiry.",
    ],
    fix: "res.cookie('session', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'lax',\n  path: '/',\n  maxAge: 1000 * 60 * 60 * 8,\n});",
  },
  {
    ruleId: "CODE-TIMING-COMPARISON",
    files: /\.(js|jsx|ts|tsx|mjs|py|rb|go|php)$/i,
    re: /(?:token|secret|signature|hmac|digest|apiKey|api_key|password)\w*\s*(?:===?|!==?)\s*\w*(?:token|secret|signature|hmac|digest|apiKey|api_key|password)/gi,
    severity: "low",
    title: "Secret compared with an ordinary equality operator",
    describe: (file, line) =>
      `${file} at line ${line} compares two secret-looking values with a standard equality operator. String comparison stops at the first differing byte, so the time it takes reveals how many leading bytes matched.`,
    exploit:
      "An attacker submits guesses and measures response time, recovering the value one byte at a time. Over a network the signal is noisy but recoverable with enough samples, and this has been used in practice against HMAC signature checks on webhooks.",
    steps: [
      "Use a constant-time comparison: crypto.timingSafeEqual in Node, hmac.compare_digest in Python, subtle.ConstantTimeCompare in Go.",
      "Ensure both values are the same length before comparing, since length differences leak separately.",
    ],
    fix: "import { timingSafeEqual } from 'node:crypto';\n\nconst a = Buffer.from(providedSignature);\nconst b = Buffer.from(expectedSignature);\nconst ok = a.length === b.length && timingSafeEqual(a, b);",
  },
];

export const codeScanner: Scanner = {
  name: "code",
  title: "Application code flaws",
  description:
    "Traces untrusted input into dangerous operations: SQL injection, command injection, path traversal, server-side request forgery, and cross-site scripting.",
  rules: RULES,

  appliesTo: (ctx) => ctx.files.some((f) => familyOf(f) !== null),

  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const out: RawFinding[] = [];
    let processed = 0;

    for (const file of ctx.files) {
      if (ctx.signal.aborted) break;
      const fam = familyOf(file);
      if (!fam) continue;

      const text = await ctx.read(file);
      if (!text) continue;
      if (++processed % 400 === 0) ctx.progress(`checked ${processed} source files`);

      const testish = isTestFile(file);
      const sourceRe = SOURCES[fam];

      for (const rule of SINKS) {
        const sinkRe = rule.sinks[fam];
        if (!sinkRe) continue;
        const seen = new Set<number>();

        for (const m of matches(sinkRe, text)) {
          if (inComment(text, m.index) || inRegexLiteral(text, m.index)) continue;
          const { line, text: lineText } = lineOf(text, m.index);
          if (seen.has(line)) continue;

          if (rule.proximity > 0) {
            const window = text.slice(
              Math.max(0, m.index - rule.proximity),
              m.index + rule.proximity,
            );
            if (!sourceRe.test(window)) continue;
          }
          seen.add(line);

          const doc = RULES.find((r) => r.id === rule.ruleId)!;
          const severity: Severity = testish
            ? "low"
            : (rule.severity ?? doc.severity);

          out.push({
            ruleId: rule.ruleId,
            title: rule.title,
            description:
              rule.describe(file, line) +
              (rule.proximity > 0
                ? " This is a proximity-based match rather than a proven dataflow path: the scanner saw an untrusted source and a dangerous sink close together. Read the code to confirm the value actually reaches the sink before treating it as exploitable."
                : ""),
            severity,
            confidence: rule.proximity > 0 ? "medium" : doc.confidence,
            evidence: `${m[0].trim().slice(0, 140)} at ${file}:${line}`,
            exploit: rule.exploit,
            remediation: {
              summary: rule.steps[0],
              steps: rule.steps,
              codeFix: rule.fix ? { language: safeLang(file), after: rule.fix } : undefined,
            },
            mappings: doc.mappings,
            tags: ["code", fam, ...(testish ? ["test-context"] : []), ...(rule.proximity > 0 ? ["needs-confirmation"] : [])],
            location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
          });
        }
      }

      for (const rule of STANDALONE) {
        if (!rule.files.test(file)) continue;
        const seen = new Set<number>();
        for (const m of matches(rule.re, text)) {
          if (inComment(text, m.index) || inRegexLiteral(text, m.index)) continue;

          // Cookie rule: only fire when a flag is genuinely absent.
          if (rule.ruleId === "CODE-COOKIE-INSECURE") {
            const block = m[0];
            const hasAll =
              /httpOnly\s*:\s*true|HttpOnly/i.test(block) &&
              /secure\s*:\s*true|;\s*Secure/i.test(block) &&
              /sameSite/i.test(block);
            if (hasAll) continue;
            if (!/session|token|auth|jwt|sid/i.test(block)) continue;
          }

          const { line, text: lineText } = lineOf(text, m.index);
          if (seen.has(line)) continue;
          seen.add(line);

          const doc = RULES.find((r) => r.id === rule.ruleId)!;
          out.push({
            ruleId: rule.ruleId,
            title: rule.title,
            description: rule.describe(file, line, m),
            severity: testish ? "info" : rule.severity,
            confidence: doc.confidence,
            evidence: `${m[0].trim().slice(0, 140)} at ${file}:${line}`,
            exploit: rule.exploit,
            remediation: {
              summary: rule.steps[0],
              steps: rule.steps,
              codeFix: rule.fix ? { language: safeLang(file), after: rule.fix } : undefined,
            },
            mappings: doc.mappings,
            tags: ["code", fam, ...(testish ? ["test-context"] : [])],
            location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
          });
        }
      }
    }

    return out;
  },
};
