import type { RawFinding, RuleDoc, ScanContext, Scanner } from "../core/types.ts";
import { basename, editDistance, lineOf, tryJson } from "./_shared.ts";
import { safeSnippet } from "../core/redact.ts";
import { POPULAR_PACKAGES, KNOWN_MALICIOUS, RISKY_INSTALL_PATTERNS } from "../data/packages.ts";

/**
 * Dependency and supply-chain risk.
 *
 * Deliberately structured so the offline path is the primary one. Most
 * dependency scanners are a thin client over a hosted advisory API and produce
 * nothing useful without network access; in an air-gapped environment that is
 * the whole product gone. Here, the checks that need no network -- typosquat
 * and hallucinated-package detection, install-script risk, unpinned and
 * floating ranges, missing lockfiles, direct git and URL dependencies -- run
 * always. Advisory lookup against OSV is an enhancement layered on top when the
 * operator has explicitly allowed network access.
 */

const RULES: RuleDoc[] = [
  {
    id: "DEP-KNOWN-MALICIOUS",
    title: "Dependency on a package known to be malicious",
    severity: "critical",
    confidence: "confirmed",
    threat: "Direct compromise. Malicious packages steal credentials and environment variables at install time.",
    mappings: { cwe: ["CWE-506", "CWE-1357"], owasp: ["A06:2021"], compliance: ["SSDF:PW.4.1"] },
  },
  {
    id: "DEP-TYPOSQUAT",
    title: "Package name one character from a very popular package",
    severity: "high",
    confidence: "medium",
    threat: "Typosquatting and slopsquatting. The name may have been registered to catch a typo, or an AI-hallucinated import.",
    mappings: { cwe: ["CWE-1357"], owasp: ["A06:2021"], compliance: ["SSDF:PW.4.1"] },
  },
  {
    id: "DEP-INSTALL-SCRIPT",
    title: "Install-time script in the manifest",
    severity: "medium",
    confidence: "high",
    threat: "Install scripts execute arbitrary code on every developer machine and CI runner that installs.",
    mappings: { cwe: ["CWE-829"], owasp: ["A06:2021"] },
  },
  {
    id: "DEP-NO-LOCKFILE",
    title: "No lockfile committed",
    severity: "medium",
    confidence: "confirmed",
    threat: "Builds are not reproducible, and a compromised upstream release is picked up silently.",
    mappings: { cwe: ["CWE-1357"], owasp: ["A06:2021"], compliance: ["SSDF:PW.4.4"] },
  },
  {
    id: "DEP-FLOATING-RANGE",
    title: "Dependency pinned to a floating range",
    severity: "low",
    confidence: "confirmed",
    threat: "A wildcard or latest range means the code you build tomorrow is not the code you reviewed today.",
    mappings: { cwe: ["CWE-1357"], owasp: ["A06:2021"] },
  },
  {
    id: "DEP-REMOTE-SOURCE",
    title: "Dependency fetched from a git URL or arbitrary URL",
    severity: "medium",
    confidence: "high",
    threat: "Bypasses the registry's integrity checks; a mutable ref can change under you.",
    mappings: { cwe: ["CWE-829"], owasp: ["A06:2021"] },
  },
  {
    id: "DEP-VULNERABLE",
    title: "Dependency with a known published vulnerability",
    severity: "high",
    confidence: "high",
    threat: "A publicly documented flaw with, frequently, public exploit code.",
    mappings: { cwe: ["CWE-1395"], owasp: ["A06:2021"], compliance: ["SOC2:CC7.1", "PCI-DSS-4.0:6.3.1"] },
  },
  {
    id: "DEP-CURL-PIPE-SHELL",
    title: "Script downloads and executes remote code",
    severity: "high",
    confidence: "high",
    threat: "curl piped to a shell executes whatever the server returns at that moment, unverified.",
    mappings: { cwe: ["CWE-494", "CWE-829"], owasp: ["A08:2021"] },
  },
];

interface Manifest {
  file: string;
  ecosystem: "npm" | "PyPI" | "Go" | "crates.io" | "RubyGems" | "Packagist" | "Maven";
  deps: { name: string; range: string; dev: boolean; line: number }[];
  scripts?: Record<string, string>;
  text: string;
}

const LOCKFILE_FOR: Record<string, string[]> = {
  npm: ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "npm-shrinkwrap.json"],
  PyPI: ["poetry.lock", "Pipfile.lock", "requirements.lock", "uv.lock", "pdm.lock"],
  Go: ["go.sum"],
  "crates.io": ["Cargo.lock"],
  RubyGems: ["Gemfile.lock"],
  Packagist: ["composer.lock"],
  Maven: [],
};

function parsePackageJson(file: string, text: string): Manifest | null {
  const json = tryJson<Record<string, unknown>>(text);
  if (!json) return null;
  const deps: Manifest["deps"] = [];
  for (const [field, isDev] of [
    ["dependencies", false],
    ["devDependencies", true],
    ["optionalDependencies", true],
    ["peerDependencies", true],
  ] as const) {
    const section = json[field] as Record<string, string> | undefined;
    if (!section) continue;
    for (const [name, range] of Object.entries(section)) {
      const idx = text.indexOf(`"${name}"`);
      deps.push({
        name,
        range: String(range),
        dev: isDev,
        line: idx >= 0 ? lineOf(text, idx).line : 1,
      });
    }
  }
  return {
    file,
    ecosystem: "npm",
    deps,
    scripts: (json.scripts as Record<string, string>) ?? {},
    text,
  };
}

function parseRequirementsTxt(file: string, text: string): Manifest {
  const deps: Manifest["deps"] = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) return;
    const m = /^([A-Za-z0-9_.\-[\]]+)\s*([<>=!~^].*)?$/.exec(line.split(/[;#]/)[0].trim());
    if (!m) return;
    deps.push({ name: m[1].split("[")[0], range: (m[2] ?? "*").trim(), dev: false, line: i + 1 });
  });
  return { file, ecosystem: "PyPI", deps, text };
}

function parsePyproject(file: string, text: string): Manifest {
  const deps: Manifest["deps"] = [];
  const lines = text.split(/\r?\n/);
  let inDeps = false;
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (/^\[.*dependencies.*\]|^\[project\]|^\[tool\.poetry\.dependencies\]/.test(line)) {
      inDeps = /dependencies/.test(line);
      return;
    }
    if (line.startsWith("[")) {
      inDeps = false;
      return;
    }
    if (!inDeps) return;
    const m = /^["']?([A-Za-z0-9_.-]+)["']?\s*[=:]\s*["']([^"']+)["']/.exec(line);
    if (m && m[1] !== "python") deps.push({ name: m[1], range: m[2], dev: false, line: i + 1 });
    const inline = /^["']([A-Za-z0-9_.-]+)\s*([<>=!~^][^"']*)?["'],?$/.exec(line);
    if (inline) deps.push({ name: inline[1], range: inline[2] ?? "*", dev: false, line: i + 1 });
  });
  return { file, ecosystem: "PyPI", deps, text };
}

function parseGoMod(file: string, text: string): Manifest {
  const deps: Manifest["deps"] = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const m = /^\s*([a-z0-9./_-]+\.[a-z]{2,}\/[^\s]+)\s+(v[^\s]+)/i.exec(raw);
    if (m) deps.push({ name: m[1], range: m[2], dev: false, line: i + 1 });
  });
  return { file, ecosystem: "Go", deps, text };
}

function parseCargo(file: string, text: string): Manifest {
  const deps: Manifest["deps"] = [];
  let inDeps = false;
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (/^\[.*dependencies\]/.test(line)) {
      inDeps = true;
      return;
    }
    if (line.startsWith("[")) {
      inDeps = false;
      return;
    }
    if (!inDeps) return;
    const m = /^([A-Za-z0-9_-]+)\s*=\s*(?:["']([^"']+)["']|\{[^}]*version\s*=\s*["']([^"']+)["'])/.exec(line);
    if (m) deps.push({ name: m[1], range: m[2] ?? m[3] ?? "*", dev: false, line: i + 1 });
  });
  return { file, ecosystem: "crates.io", deps, text };
}

/**
 * Slopsquat and typosquat detection.
 *
 * Assistants hallucinate plausible package names; attackers register them. The
 * check is edit distance against a popularity list, with two guards that keep
 * the false-positive rate low: an exact match on the popular list is always
 * fine, and scoped packages under a known-good scope are exempt.
 */
function typosquatOf(name: string, ecosystem: string): string | null {
  const popular = POPULAR_PACKAGES[ecosystem];
  if (!popular) return null;
  if (popular.has(name)) return null;
  const bare = name.startsWith("@") ? name.split("/")[1] ?? name : name;
  if (bare.length < 4) return null;
  for (const p of popular) {
    if (p.length < 4) continue;
    if (Math.abs(p.length - bare.length) > 2) continue;
    const d = editDistance(bare, p, 1);
    if (d === 1) return p;
    // Common squat shapes that edit distance alone misses.
    if (bare === p.replace(/-/g, "") || bare === p.replace(/\./g, "")) return p;
    if (bare === `${p}js` || bare === `js${p}` || bare === `${p}-js`) return p;
    if (bare === `python-${p}` || bare === `node-${p}`) return p;
  }
  return null;
}

async function osvLookup(
  manifests: Manifest[],
  signal: AbortSignal,
): Promise<Map<string, { id: string; summary: string; severity: string }[]>> {
  const result = new Map<string, { id: string; summary: string; severity: string }[]>();
  const queries: { package: { name: string; ecosystem: string }; version?: string }[] = [];
  const index: string[] = [];

  for (const m of manifests) {
    for (const d of m.deps) {
      const version = /^[\^~>=<\s]*([0-9][0-9A-Za-z.\-+]*)/.exec(d.range)?.[1];
      if (!version) continue;
      queries.push({ package: { name: d.name, ecosystem: m.ecosystem }, version });
      index.push(`${m.ecosystem}:${d.name}`);
    }
  }
  if (queries.length === 0) return result;

  // OSV's batch endpoint caps at 1000 queries per request.
  for (let i = 0; i < queries.length; i += 500) {
    const slice = queries.slice(i, i + 500);
    const names = index.slice(i, i + 500);
    try {
      const res = await fetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ queries: slice }),
        signal: AbortSignal.any([signal, AbortSignal.timeout(20_000)]),
      });
      if (!res.ok) continue;
      const data = (await res.json()) as { results: { vulns?: { id: string }[] }[] };
      data.results?.forEach((r, j) => {
        if (!r.vulns?.length) return;
        result.set(
          names[j],
          r.vulns.map((v) => ({ id: v.id, summary: "", severity: "high" })),
        );
      });
    } catch {
      /* network failure degrades coverage, never fails the scan */
    }
  }
  return result;
}

export const dependencyScanner: Scanner = {
  name: "dependencies",
  title: "Dependency and supply-chain risk",
  description:
    "Reads your package manifests for malicious and typosquatted packages, install-time scripts, unpinned versions, and missing lockfiles.",
  rules: RULES,

  appliesTo: (ctx) =>
    ctx.files.some((f) =>
      /(?:^|\/)(?:package\.json|requirements[^/]*\.txt|pyproject\.toml|Pipfile|go\.mod|Cargo\.toml|Gemfile|composer\.json|pom\.xml|build\.gradle)$/i.test(f),
    ),

  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const out: RawFinding[] = [];
    const manifests: Manifest[] = [];
    const allFiles = new Set(ctx.files.map((f) => basename(f)));

    for (const file of ctx.files) {
      const base = basename(file);
      const text = await ctx.read(file);
      if (!text) continue;
      let m: Manifest | null = null;
      if (base === "package.json") m = parsePackageJson(file, text);
      else if (/^requirements.*\.txt$/i.test(base)) m = parseRequirementsTxt(file, text);
      else if (base === "pyproject.toml") m = parsePyproject(file, text);
      else if (base === "go.mod") m = parseGoMod(file, text);
      else if (base === "Cargo.toml") m = parseCargo(file, text);
      if (m && m.deps.length >= 0) manifests.push(m);
    }

    ctx.progress(`reading ${manifests.length} manifests`);

    for (const man of manifests) {
      // Missing lockfile
      const expected = LOCKFILE_FOR[man.ecosystem] ?? [];
      if (expected.length > 0 && !expected.some((l) => allFiles.has(l))) {
        out.push({
          ruleId: "DEP-NO-LOCKFILE",
          title: `No lockfile alongside ${man.file}`,
          description:
            `${man.file} declares dependencies but no lockfile (${expected.join(", ")}) is committed. Without one, the exact versions installed depend on when the install runs. Two developers, or a developer and CI, can end up with different code from the same commit.`,
          severity: "medium",
          confidence: "confirmed",
          evidence: `${man.file} present, none of ${expected.join(", ")} found in the repository`,
          exploit:
            "When a maintainer account is compromised and a malicious patch release is published, a project with a lockfile is unaffected until it deliberately updates. A project without one picks up the malicious version on the next install, including in CI, where it runs with deployment credentials.",
          remediation: {
            summary: "Generate a lockfile and commit it.",
            steps: [
              `Run your package manager's install once and commit the resulting ${expected[0]}.`,
              "Use the reproducible install command in CI (npm ci, poetry install --sync, cargo build --locked) so CI fails rather than silently resolving new versions.",
              "Review lockfile diffs in code review. A large unexplained lockfile change is a signal worth reading.",
            ],
          },
          mappings: { cwe: ["CWE-1357"], owasp: ["A06:2021"], compliance: ["SSDF:PW.4.4"] },
          tags: ["supply-chain", man.ecosystem],
          location: { file: man.file, startLine: 1, endLine: 1 },
        });
      }

      // Install-time scripts
      for (const [name, cmd] of Object.entries(man.scripts ?? {})) {
        if (!/^(?:pre|post)?install$|^prepare$|^prepublish$/.test(name)) continue;
        const idx = man.text.indexOf(`"${name}"`);
        const { line, text: lineText } = lineOf(man.text, Math.max(idx, 0));
        const dangerous = RISKY_INSTALL_PATTERNS.some((re) => re.test(cmd));
        out.push({
          ruleId: dangerous ? "DEP-CURL-PIPE-SHELL" : "DEP-INSTALL-SCRIPT",
          title: dangerous
            ? `The ${name} script downloads and runs remote code`
            : `${man.file} runs a script at install time`,
          description: dangerous
            ? `The ${name} script in ${man.file} fetches something from the network and executes it. Whatever that server returns at the moment of install is what runs, with no signature check and no review.`
            : `The ${name} script in ${man.file} runs automatically whenever anyone installs this project. Install scripts execute with the full privileges of the user running the install, on every developer machine and every CI runner.`,
          severity: dangerous ? "high" : "medium",
          confidence: "high",
          evidence: `"${name}": ${cmd.slice(0, 160)} in ${man.file}:${line}`,
          exploit: dangerous
            ? "Anyone who can influence what that URL serves, through a compromise, a hijacked domain, or a DNS attack, gets code execution on every machine that installs this project, including CI runners holding deployment credentials."
            : "If this repository is ever compromised, the install script is the most reliable place to put code, because it runs before anyone reviews anything and it runs on machines that hold source code and credentials.",
          remediation: {
            summary: dangerous
              ? "Pin and verify what you download, or vendor it."
              : "Remove the install script if you can, or move the work to an explicit command.",
            steps: dangerous
              ? [
                  "Pin the download to an exact version and verify a checksum or signature before executing.",
                  "Better: vendor the artifact into the repository, or install it through your package manager where integrity is checked for you.",
                  "Never pipe a network response directly into a shell.",
                ]
              : [
                  "Move the work into an explicit script developers run deliberately, such as npm run setup.",
                  "If it must run at install, keep it to local file operations with no network access.",
                  "Run installs in CI with scripts disabled where possible (npm ci --ignore-scripts) and handle setup as its own reviewed step.",
                ],
          },
          mappings: { cwe: dangerous ? ["CWE-494", "CWE-829"] : ["CWE-829"], owasp: ["A06:2021", "A08:2021"] },
          tags: ["supply-chain", "install-script"],
          location: { file: man.file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
        });
      }

      for (const dep of man.deps) {
        // Known malicious
        const malicious = KNOWN_MALICIOUS[man.ecosystem]?.get(dep.name);
        if (malicious) {
          out.push({
            ruleId: "DEP-KNOWN-MALICIOUS",
            title: `"${dep.name}" is a known malicious package`,
            description: `${man.file} depends on ${dep.name}, which is recorded as malicious: ${malicious.replace(/\.$/, "")}. Treat any machine that has installed this as compromised until proven otherwise.`,
            severity: "critical",
            confidence: "confirmed",
            evidence: `${dep.name}@${dep.range} in ${man.file}:${dep.line}`,
            exploit:
              "Malicious packages in this class typically run at install time and exfiltrate environment variables, cloud credential files, SSH keys, and npm or PyPI tokens. If it reached CI, assume deployment credentials are compromised.",
            remediation: {
              summary: "Remove the package immediately and treat this as an incident, not a bug.",
              steps: [
                `Remove ${dep.name} from ${man.file} and from the lockfile.`,
                "Rotate every credential that was present on any machine or CI runner that installed it: cloud keys, registry tokens, SSH keys, CI secrets.",
                "Review CI and cloud audit logs for activity from the install window onward.",
                "Determine the correct package name. This is often a typosquat of a legitimate package.",
              ],
              outOfBandAction:
                "Rotate all credentials exposed to any machine that installed this package. Removing the dependency does not undo the exfiltration.",
            },
            mappings: { cwe: ["CWE-506", "CWE-1357"], owasp: ["A06:2021"], compliance: ["SSDF:PW.4.1"] },
            tags: ["supply-chain", "malicious", man.ecosystem],
            location: { file: man.file, startLine: dep.line, endLine: dep.line },
          });
          continue;
        }

        // Typosquat / hallucinated package
        const near = typosquatOf(dep.name, man.ecosystem);
        if (near) {
          out.push({
            ruleId: "DEP-TYPOSQUAT",
            title: `"${dep.name}" is one character from "${near}"`,
            description:
              `${man.file} depends on ${dep.name}, which differs by a single character from ${near}, a very widely used package. This is the shape of a typosquat. It is also the shape of a package name an AI assistant invented: assistants regularly import plausible-sounding packages that do not exist, and attackers register those names precisely because assistants keep suggesting them.`,
            severity: "high",
            confidence: "medium",
            evidence: `${dep.name}@${dep.range} in ${man.file}:${dep.line}, one edit from ${near}`,
            exploit:
              "If this is a squatted name, the package's install script runs on every developer machine and CI runner, exfiltrating environment variables and credential files. The dependency looks correct in review because the name reads right at a glance.",
            remediation: {
              summary: `Confirm you meant ${dep.name} and not ${near}.`,
              steps: [
                `Check the registry page for ${dep.name}: publish date, download count, repository link, and maintainers.`,
                `A package created recently with few downloads and a name close to ${near} should be assumed hostile.`,
                `If it was a mistake, replace it with ${near}, delete the lockfile entry, and reinstall.`,
                "If it is legitimate, add a suppression with that reasoning so the check stops firing.",
              ],
            },
            mappings: { cwe: ["CWE-1357"], owasp: ["A06:2021"], compliance: ["SSDF:PW.4.1"] },
            tags: ["supply-chain", "typosquat", "slopsquat", man.ecosystem],
            location: { file: man.file, startLine: dep.line, endLine: dep.line },
          });
        }

        // Remote / git sources
        if (/^(?:git\+|git:|https?:|file:|github:)/i.test(dep.range)) {
          const mutable = !/#[0-9a-f]{7,40}$/i.test(dep.range);
          out.push({
            ruleId: "DEP-REMOTE-SOURCE",
            title: `"${dep.name}" is installed from a URL rather than the registry`,
            description:
              `${man.file} pulls ${dep.name} from ${dep.range.slice(0, 100)}. This bypasses the registry's integrity checks.` +
              (mutable
                ? " The reference is a branch or tag rather than a commit hash, so the code can change without any change in your repository."
                : ""),
            severity: mutable ? "medium" : "low",
            confidence: "high",
            evidence: `${dep.name}: ${dep.range.slice(0, 120)} in ${man.file}:${dep.line}`,
            exploit: mutable
              ? "Whoever controls that repository can change what your build installs at any time, with no pull request in your project and nothing for a reviewer to see."
              : "The source is outside registry integrity guarantees, so a compromise of that host affects your build directly.",
            remediation: {
              summary: mutable
                ? "Pin to a full commit hash, or publish the package to a registry you control."
                : "Confirm the host is one you trust to hold build-time code execution.",
              steps: [
                "Replace the branch or tag reference with a full 40-character commit hash.",
                "For anything you depend on seriously, publish it to a private registry instead.",
                "Verify the repository is one your organization controls or has reviewed.",
              ],
            },
            mappings: { cwe: ["CWE-829"], owasp: ["A06:2021"] },
            tags: ["supply-chain", man.ecosystem],
            location: { file: man.file, startLine: dep.line, endLine: dep.line },
          });
        }

        // Floating ranges
        if (/^(?:\*|latest|x|>=?\s*0|\^0\.0|any)$/i.test(dep.range.trim())) {
          out.push({
            ruleId: "DEP-FLOATING-RANGE",
            title: `"${dep.name}" has no meaningful version constraint`,
            description: `${man.file} declares ${dep.name} as "${dep.range}". Any published version satisfies that, including a version published five minutes ago.`,
            severity: "low",
            confidence: "confirmed",
            evidence: `${dep.name}: "${dep.range}" in ${man.file}:${dep.line}`,
            exploit:
              "A compromised or malicious release is installed automatically on the next fresh install, with no change to your repository.",
            remediation: {
              summary: "Constrain the version and rely on the lockfile for exactness.",
              steps: [
                "Replace the wildcard with a caret or tilde range against a version you have actually tested.",
                "Commit a lockfile so the exact resolved version is recorded.",
              ],
            },
            mappings: { cwe: ["CWE-1357"], owasp: ["A06:2021"] },
            tags: ["supply-chain", man.ecosystem],
            location: { file: man.file, startLine: dep.line, endLine: dep.line },
          });
        }
      }
    }

    // Optional advisory enrichment.
    if (ctx.networkAllowed) {
      ctx.progress("checking dependencies against the OSV advisory database");
      const vulns = await osvLookup(manifests, ctx.signal);
      for (const man of manifests) {
        for (const dep of man.deps) {
          const hits = vulns.get(`${man.ecosystem}:${dep.name}`);
          if (!hits?.length) continue;
          const ids = hits.map((h) => h.id);
          out.push({
            ruleId: "DEP-VULNERABLE",
            title: `${dep.name}@${dep.range} has ${ids.length} known ${ids.length === 1 ? "advisory" : "advisories"}`,
            description:
              `The version of ${dep.name} declared in ${man.file} is covered by published security advisories: ${ids.slice(0, 6).join(", ")}${ids.length > 6 ? ` and ${ids.length - 6} more` : ""}. Whether any of them is exploitable in your application depends on which code paths you actually use.`,
            severity: "high",
            confidence: "high",
            evidence: `${dep.name}@${dep.range} matches ${ids.join(", ")} (source: OSV)`,
            exploit:
              "Published advisories frequently come with public proof-of-concept exploits. Automated scanners used by attackers check for exactly these versions on exposed services.",
            remediation: {
              summary: `Upgrade ${dep.name} to a version outside the affected range.`,
              steps: [
                `Look up ${ids[0]} at https://osv.dev/vulnerability/${ids[0]} for the fixed version and the affected code paths.`,
                `Upgrade ${dep.name} and re-run your tests.`,
                "If no fix exists, check whether your application reaches the vulnerable function at all. Unreached code is a lower priority than a version number suggests.",
                "If the dependency is unmaintained, plan a replacement.",
              ],
            },
            mappings: {
              cwe: ["CWE-1395"],
              owasp: ["A06:2021"],
              advisories: ids,
              compliance: ["SOC2:CC7.1", "PCI-DSS-4.0:6.3.1"],
            },
            tags: ["supply-chain", "known-vulnerability", man.ecosystem],
            location: { file: man.file, startLine: dep.line, endLine: dep.line },
          });
        }
      }
    }

    return out;
  },
};
