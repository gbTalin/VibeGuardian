import type { RawFinding, RuleDoc, ScanContext, Scanner, Severity } from "../core/types.ts";
import { basename, lineOf, matches } from "./_shared.ts";
import { safeSnippet } from "../core/redact.ts";

/**
 * Infrastructure-as-code misconfiguration.
 *
 * IaC is where a one-line mistake becomes a permanent, replicated exposure. The
 * value of checking it locally is that these files describe infrastructure that
 * may not exist yet -- catching an open security group in a pull request costs
 * nothing, catching it in production costs an incident.
 */

const RULES: RuleDoc[] = [
  {
    id: "IAC-OPEN-INGRESS",
    title: "Network rule open to the entire internet",
    severity: "high",
    confidence: "high",
    threat: "Direct exposure of a service to every host on the internet, including automated scanners.",
    mappings: { cwe: ["CWE-284", "CWE-668"], owasp: ["A05:2021"], compliance: ["SOC2:CC6.6", "PCI-DSS-4.0:1.3.1"] },
  },
  {
    id: "IAC-OPEN-ADMIN-PORT",
    title: "Administrative port open to the internet",
    severity: "critical",
    confidence: "high",
    threat: "SSH, RDP, or a database port reachable from anywhere is continuously brute-forced.",
    mappings: { cwe: ["CWE-284"], owasp: ["A05:2021"], compliance: ["PCI-DSS-4.0:1.3.1"] },
  },
  {
    id: "IAC-PUBLIC-BUCKET",
    title: "Object storage configured for public access",
    severity: "high",
    confidence: "high",
    threat: "Anyone can list or download stored objects.",
    mappings: { cwe: ["CWE-732"], owasp: ["A01:2021"], compliance: ["SOC2:CC6.1", "GDPR:Art32"] },
  },
  {
    id: "IAC-NO-ENCRYPTION",
    title: "Storage or database created without encryption at rest",
    severity: "medium",
    confidence: "high",
    threat: "Data is readable from a stolen snapshot, backup, or underlying volume.",
    mappings: { cwe: ["CWE-311"], owasp: ["A02:2021"], compliance: ["PCI-DSS-4.0:3.5.1", "HIPAA:164.312(a)(2)(iv)"] },
  },
  {
    id: "IAC-WILDCARD-IAM",
    title: "IAM policy grants all actions on all resources",
    severity: "critical",
    confidence: "high",
    threat: "Anything that assumes this role has full control of the account.",
    mappings: { cwe: ["CWE-269", "CWE-732"], owasp: ["A01:2021"], compliance: ["SOC2:CC6.3"] },
  },
  {
    id: "IAC-PLAINTEXT-SECRET",
    title: "Secret written in plain text in an infrastructure file",
    severity: "critical",
    confidence: "high",
    threat: "The value is committed to source and copied into the state file.",
    mappings: { cwe: ["CWE-798"], owasp: ["A07:2021"], compliance: ["SOC2:CC6.1"] },
  },
  {
    id: "IAC-CONTAINER-PRIVILEGED",
    title: "Container runs privileged or as root",
    severity: "high",
    confidence: "high",
    threat: "A container escape becomes a host compromise.",
    mappings: { cwe: ["CWE-250", "CWE-269"], owasp: ["A05:2021"], compliance: ["CIS-K8s:5.2.1"] },
  },
  {
    id: "IAC-HOST-MOUNT",
    title: "Container mounts a sensitive host path",
    severity: "high",
    confidence: "high",
    threat: "Mounting the Docker socket or the host root gives the container control of the node.",
    mappings: { cwe: ["CWE-668"], owasp: ["A05:2021"], compliance: ["CIS-K8s:5.2.4"] },
  },
  {
    id: "IAC-NO-LOGGING",
    title: "Audit logging not enabled",
    severity: "medium",
    confidence: "medium",
    threat: "Without logs there is no way to determine what happened during an incident.",
    mappings: { cwe: ["CWE-778"], owasp: ["A09:2021"], compliance: ["SOC2:CC7.2", "PCI-DSS-4.0:10.2.1"] },
  },
  {
    id: "IAC-DOCKER-LATEST",
    title: "Container image referenced by a mutable tag",
    severity: "low",
    confidence: "confirmed",
    threat: "The image that runs tomorrow is not the image that was reviewed today.",
    mappings: { cwe: ["CWE-1357"], owasp: ["A08:2021"], compliance: ["SLSA:L2"] },
  },
  {
    id: "IAC-DOCKER-ROOT",
    title: "Dockerfile does not drop to a non-root user",
    severity: "medium",
    confidence: "high",
    threat: "Any code execution in the container is immediately root inside it.",
    mappings: { cwe: ["CWE-250"], owasp: ["A05:2021"], compliance: ["CIS-Docker:4.1"] },
  },
  {
    id: "IAC-PUBLIC-DB",
    title: "Managed database made publicly accessible",
    severity: "critical",
    confidence: "high",
    threat: "The database endpoint is reachable from the internet.",
    mappings: { cwe: ["CWE-284"], owasp: ["A05:2021"], compliance: ["PCI-DSS-4.0:1.3.1"] },
  },
];

interface Check {
  ruleId: string;
  re: RegExp;
  files: RegExp;
  severity?: Severity;
  title: string;
  describe: (file: string, line: number, m: RegExpExecArray) => string;
  exploit: string;
  steps: string[];
  fixAfter?: { language: string; after: string };
  guard?: (m: RegExpExecArray, text: string) => boolean;
}

const TF = /\.tf$|\.tf\.json$|\.tfvars$/i;
const K8S = /\.ya?ml$/i;
const DOCKERFILE = /(?:^|\/)Dockerfile(?:\.[\w-]+)?$/i;
const COMPOSE = /(?:^|\/)docker-compose(?:\.[\w-]+)?\.ya?ml$/i;
const CFN = /\.(?:ya?ml|json)$/i;

const CHECKS: Check[] = [
  {
    ruleId: "IAC-OPEN-ADMIN-PORT",
    files: TF,
    re: /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\][\s\S]{0,300}?from_port\s*=\s*(22|3389|3306|5432|27017|6379|9200|1433|5984|11211)\b|from_port\s*=\s*(22|3389|3306|5432|27017|6379|9200|1433|5984|11211)\b[\s\S]{0,300}?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/g,
    severity: "critical",
    title: "An administrative port is open to the whole internet",
    describe: (file, line, m) => {
      const port = m[1] ?? m[2];
      const names: Record<string, string> = {
        "22": "SSH", "3389": "RDP", "3306": "MySQL", "5432": "PostgreSQL",
        "27017": "MongoDB", "6379": "Redis", "9200": "Elasticsearch", "1433": "SQL Server",
        "5984": "CouchDB", "11211": "Memcached",
      };
      return `${file} at line ${line} opens port ${port} (${names[port] ?? "an administrative service"}) to 0.0.0.0/0, meaning every address on the internet. Services on this port are scanned continuously by automated tooling; exposure is measured in minutes, not days.`;
    },
    exploit:
      "Internet-wide scanners find this within minutes of it going live. Databases on these ports are frequently deployed with default or absent authentication, which has produced repeated mass-ransom campaigns against exposed MongoDB, Elasticsearch, and Redis instances. For SSH and RDP, credential stuffing runs continuously.",
    steps: [
      "Replace 0.0.0.0/0 with the specific CIDR ranges that genuinely need access.",
      "For administrative access, prefer a bastion host, AWS Systems Manager Session Manager, or a VPN, so the port is never internet-facing.",
      "Databases should sit in a private subnet with no public route at all.",
      "If this is already deployed, check access logs before assuming it was not found.",
    ],
    fixAfter: {
      language: "hcl",
      after: 'ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = [var.trusted_admin_cidr]  # not 0.0.0.0/0\n}',
    },
  },
  {
    ruleId: "IAC-OPEN-INGRESS",
    files: TF,
    re: /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/g,
    title: "A network rule allows traffic from anywhere",
    describe: (file, line) =>
      `${file} at line ${line} allows inbound traffic from 0.0.0.0/0. This is correct for a public web listener on 80 or 443 and wrong for almost everything else.`,
    exploit:
      "Every service behind this rule is reachable by anyone. If it is a web port fronting an application, this is expected. If it is anything else, it is an unintended entry point that scanners will find.",
    steps: [
      "Confirm this rule is for a genuinely public listener, typically HTTP or HTTPS.",
      "If it is, narrow the port range so it covers only those ports.",
      "If it is not, replace the CIDR with the specific ranges that need access.",
    ],
  },
  {
    ruleId: "IAC-PUBLIC-DB",
    files: TF,
    re: /publicly_accessible\s*=\s*true/g,
    severity: "critical",
    title: "Managed database is publicly accessible",
    describe: (file, line) =>
      `${file} at line ${line} sets publicly_accessible = true on a managed database. The instance gets a public endpoint reachable from the internet, and only the security group stands between it and the world.`,
    exploit:
      "Attackers enumerate cloud database endpoints continuously. Combined with a permissive security group, weak credentials, or a leaked connection string, this is a direct path to the entire dataset.",
    steps: [
      "Set publicly_accessible = false.",
      "Place the instance in private subnets and reach it from application subnets only.",
      "If external access is genuinely required, front it with a bastion or a VPN rather than a public endpoint.",
    ],
  },
  {
    ruleId: "IAC-WILDCARD-IAM",
    files: /\.(tf|json|ya?ml)$/i,
    re: /"Action"\s*:\s*"\*"[\s\S]{0,200}?"Resource"\s*:\s*"\*"|"Resource"\s*:\s*"\*"[\s\S]{0,200}?"Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\][\s\S]{0,200}?resources\s*=\s*\[\s*"\*"\s*\]/g,
    severity: "critical",
    title: "An IAM policy grants every action on every resource",
    describe: (file, line) =>
      `${file} at line ${line} defines a policy allowing Action "*" on Resource "*". Whatever holds this policy has complete control of the account: it can read every bucket, create users, disable logging, and delete backups.`,
    exploit:
      "Any compromise of the entity holding this policy is a full account takeover rather than a contained incident. Attackers who obtain credentials specifically enumerate permissions first, and a wildcard policy converts a minor foothold into total control, including the ability to disable the logging that would reveal them.",
    steps: [
      "Enumerate the actions this principal actually performs, from CloudTrail or from the code.",
      "Write a policy listing exactly those actions against exactly those resource ARNs.",
      "Use AWS Access Analyzer, or the equivalent in your cloud, to generate a least-privilege policy from observed usage.",
      "If this is a break-glass administrative role, require MFA and alert on every assumption of it.",
    ],
    fixAfter: {
      language: "json",
      after: '{\n  "Effect": "Allow",\n  "Action": ["s3:GetObject", "s3:PutObject"],\n  "Resource": "arn:aws:s3:::my-bucket/uploads/*"\n}',
    },
  },
  {
    ruleId: "IAC-PUBLIC-BUCKET",
    files: /\.(tf|ya?ml|json)$/i,
    re: /acl\s*=\s*"public-read(?:-write)?"|"AccessControl"\s*:\s*"PublicRead(?:Write)?"|block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|ignore_public_acls\s*=\s*false|restrict_public_buckets\s*=\s*false/g,
    title: "Object storage is open to the public",
    describe: (file, line) =>
      `${file} at line ${line} configures a storage bucket for public access, or disables one of the guards that would prevent it. Public buckets are one of the most common causes of large-scale data exposure.`,
    exploit:
      "Attackers enumerate bucket names continuously and index what they find. If the bucket holds user uploads, backups, logs, or configuration, all of it is retrievable by anyone. No credential is required and nothing appears anomalous in your logs.",
    steps: [
      "Enable all four public-access-block settings on the bucket and at the account level.",
      "Serve genuinely public assets through a CDN with an origin access identity rather than a public bucket.",
      "Use short-lived presigned URLs for user-specific downloads.",
      "If this is already deployed, audit what is in the bucket. Exposure of personal data may trigger notification duties.",
    ],
  },
  {
    ruleId: "IAC-NO-ENCRYPTION",
    files: TF,
    re: /(?:storage_encrypted\s*=\s*false|encrypted\s*=\s*false|encryption_enabled\s*=\s*false|enable_encryption\s*=\s*false)/g,
    title: "Encryption at rest is switched off",
    describe: (file, line) =>
      `${file} at line ${line} explicitly disables encryption at rest. On every major cloud this is free and enabled by default, so switching it off is a deliberate step backwards.`,
    exploit:
      "Data is readable from any copy of the underlying storage: a snapshot shared to the wrong account, a backup restored elsewhere, or the physical media. Several compliance regimes treat unencrypted storage of regulated data as a finding in itself, independent of any breach.",
    steps: [
      "Remove the setting, or set it to true, and specify a KMS key you control.",
      "Existing resources usually need a snapshot-and-restore to become encrypted; plan the migration.",
      "Add a policy check that blocks future unencrypted resources at plan time.",
    ],
  },
  {
    ruleId: "IAC-PLAINTEXT-SECRET",
    files: /\.(tf|tfvars)$/i,
    re: /^\s*(?:password|secret|api_key|access_key|private_key|token|client_secret)\s*=\s*"((?!\$\{|var\.|data\.|local\.|random_)[^"]{8,})"/gim,
    severity: "critical",
    title: "A secret is written in plain text in a Terraform file",
    describe: (file, line) =>
      `${file} at line ${line} assigns a credential as a literal string. Beyond being committed to source, Terraform writes every attribute into the state file, so the value also lands wherever your state is stored, in plain text.`,
    exploit:
      "Anyone with repository access has the credential, and so does anyone with read access to the Terraform state bucket, which is frequently granted more broadly than repository access because it is thought of as infrastructure metadata rather than a secret store.",
    steps: [
      "Move the value to a secret manager and reference it through a data source.",
      "Rotate the credential; it is in git history and in every state file version.",
      "Ensure the state backend is encrypted and access to it is restricted and logged.",
    ],
    fixAfter: {
      language: "hcl",
      after: 'data "aws_secretsmanager_secret_version" "db" {\n  secret_id = "prod/db/password"\n}\n\nresource "aws_db_instance" "main" {\n  password = data.aws_secretsmanager_secret_version.db.secret_string\n}',
    },
  },
  {
    ruleId: "IAC-CONTAINER-PRIVILEGED",
    files: K8S,
    re: /privileged\s*:\s*true|allowPrivilegeEscalation\s*:\s*true|runAsUser\s*:\s*0\b|hostPID\s*:\s*true|hostNetwork\s*:\s*true|hostIPC\s*:\s*true/g,
    title: "Container is granted host-level privileges",
    describe: (file, line, m) =>
      `${file} at line ${line} sets ${m[0].trim()}. This removes a boundary that normally separates the container from the node it runs on.`,
    exploit:
      "A privileged container can access host devices, load kernel modules, and mount the host filesystem. Any code execution inside it, whether from a vulnerable dependency or a compromised image, becomes control of the node and, from there, of every other workload scheduled on it.",
    steps: [
      "Remove the privileged flag. Most workloads that request it do not need it.",
      "If a specific capability is required, grant that one capability rather than full privilege.",
      "Set runAsNonRoot: true and allowPrivilegeEscalation: false in the security context.",
      "Enforce this cluster-wide with Pod Security Admission at the restricted level.",
    ],
    fixAfter: {
      language: "yaml",
      after: "securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001\n  allowPrivilegeEscalation: false\n  readOnlyRootFilesystem: true\n  capabilities:\n    drop: [\"ALL\"]",
    },
  },
  {
    ruleId: "IAC-HOST-MOUNT",
    files: /\.ya?ml$/i,
    re: /path\s*:\s*\/var\/run\/docker\.sock|-\s*\/var\/run\/docker\.sock|path\s*:\s*["']?\/["']?\s*$|-\s*\/:\/host|hostPath\s*:\s*[\s\S]{0,60}?path\s*:\s*["']?\/(?:etc|root|var\/lib)/g,
    title: "Container mounts a sensitive host path",
    describe: (file, line, m) =>
      `${file} at line ${line} mounts a host path into a container: ${m[0].trim().slice(0, 60)}. Mounting the Docker socket or a system directory is equivalent to granting root on the host.`,
    exploit:
      "With the Docker socket mounted, a process in the container starts a new privileged container mounting the host root, and reads or writes anything on the node. This is the standard container-escape technique and it needs no vulnerability, only the mount.",
    steps: [
      "Remove the mount. If the workload needs to talk to a container runtime, use a scoped proxy that permits only the specific calls required.",
      "Never mount / , /etc, /root, or /var/lib into a container.",
      "Enforce a policy that blocks hostPath volumes for anything except explicitly reviewed system workloads.",
    ],
  },
  {
    ruleId: "IAC-DOCKER-LATEST",
    files: /(?:^|\/)Dockerfile(?:\.[\w-]+)?$|\.ya?ml$/i,
    re: /^\s*FROM\s+([^\s:@]+)(?::latest)?\s*$|image\s*:\s*["']?([^\s"':@]+):latest["']?/gim,
    severity: "low",
    title: "Container image uses a mutable tag",
    describe: (file, line) =>
      `${file} at line ${line} refers to an image without a digest, so it resolves to whatever the registry currently serves for that tag. Two deploys from the same commit can run different code.`,
    exploit:
      "If the upstream image is compromised or simply changes, the new content is pulled on the next deploy with no change in your repository. Rollback also stops being reliable, because the old tag may no longer point at the old image.",
    steps: [
      "Pin by digest: FROM node:22.11.0-alpine@sha256:<digest>.",
      "Automate digest bumps through your dependency update tool so upgrades stay reviewable.",
      "Mirror critical base images into a registry you control.",
    ],
  },
  {
    ruleId: "IAC-NO-LOGGING",
    files: TF,
    re: /enable_logging\s*=\s*false|logging\s*=\s*false|cloudwatch_logs_enabled\s*=\s*false|enable_key_rotation\s*=\s*false/g,
    title: "Logging or key rotation is disabled",
    describe: (file, line, m) =>
      `${file} at line ${line} sets ${m[0].trim()}. Audit logs are what turn "something happened" into "here is exactly what happened and when".`,
    exploit:
      "Without logs, an intrusion cannot be scoped. You cannot tell what was accessed, when it started, or whether it is over, which converts a contained incident into a full breach notification because you are unable to prove otherwise.",
    steps: [
      "Enable logging and ship logs to a separate account or project that the workload's credentials cannot write to.",
      "Set a retention period that matches your regulatory obligations.",
      "Enable key rotation where it was disabled.",
    ],
  },
];

/** Dockerfiles that never drop privileges. Whole-file check rather than a line match. */
function dockerfileUserCheck(file: string, text: string): RawFinding[] {
  if (!DOCKERFILE.test(file)) return [];
  if (/^\s*USER\s+(?!root\s*$)[\w$:{}.-]+/im.test(text)) return [];
  const from = /^\s*FROM\s+.*/im.exec(text);
  if (!from) return [];
  if (/scratch|distroless|(?:^|\/)nonroot/i.test(from[0])) return [];
  const { line, text: lineText } = lineOf(text, from.index);
  return [
    {
      ruleId: "IAC-DOCKER-ROOT",
      title: `${file} never switches to a non-root user`,
      description:
        `${file} has no USER instruction, so every process in the container runs as root. Container root is not host root, but it removes a whole layer of defence and makes several escape techniques easier.`,
      severity: "medium",
      confidence: "high",
      evidence: `no USER instruction in ${file}`,
      exploit:
        "Any code execution inside the container, from a vulnerable dependency or a file upload flaw, is immediately root within the container: it can write anywhere in the filesystem, install tooling, and modify the application. If the container is also privileged or has a host mount, it reaches the node from there.",
      remediation: {
        summary: "Create an unprivileged user and switch to it before the entrypoint.",
        steps: [
          "Add a non-root user in the image and switch to it with USER before CMD or ENTRYPOINT.",
          "Ensure the application's working directory is writable by that user.",
          "For ports below 1024, bind higher in the container and map at the host or service layer.",
        ],
        codeFix: {
          language: "dockerfile",
          after: "RUN addgroup -S app && adduser -S -G app app\nWORKDIR /app\nCOPY --chown=app:app . .\nUSER app\nCMD [\"node\", \"server.js\"]",
        },
      },
      mappings: { cwe: ["CWE-250"], owasp: ["A05:2021"], compliance: ["CIS-Docker:4.1"] },
      tags: ["iac", "container", "docker"],
      location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
    },
  ];
}

export const iacScanner: Scanner = {
  name: "iac",
  title: "Infrastructure configuration",
  description:
    "Reads your Terraform, Kubernetes, and Docker files for open ports, public storage, over-broad permissions, and containers with host access.",
  rules: RULES,

  appliesTo: (ctx) =>
    ctx.files.some(
      (f) => TF.test(f) || DOCKERFILE.test(f) || COMPOSE.test(f) || (K8S.test(f) && !/\.github\//.test(f)),
    ),

  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const out: RawFinding[] = [];
    let processed = 0;

    for (const file of ctx.files) {
      if (ctx.signal.aborted) break;
      const relevant =
        TF.test(file) || DOCKERFILE.test(file) || COMPOSE.test(file) || CFN.test(file);
      if (!relevant) continue;
      if (/\.github\/workflows\//.test(file)) continue; // owned by the CI scanner

      const text = await ctx.read(file);
      if (!text) continue;
      if (++processed % 200 === 0) ctx.progress(`checked ${processed} infrastructure files`);

      out.push(...dockerfileUserCheck(file, text));

      // Kubernetes and CloudFormation share the YAML extension with a lot of
      // unrelated config, so require a recognisable marker before applying the
      // manifest rules. Without this the scanner fires on every CI config,
      // OpenAPI spec, and i18n file in the repo.
      const looksK8s = /^\s*(?:apiVersion|kind)\s*:/m.test(text);
      const looksCfn = /AWSTemplateFormatVersion|^\s*Resources\s*:/m.test(text);
      const looksCompose = COMPOSE.test(file);
      if (K8S.test(file) && !looksK8s && !looksCfn && !looksCompose && !TF.test(file)) continue;

      for (const check of CHECKS) {
        if (!check.files.test(file)) continue;
        const seen = new Set<number>();
        for (const m of matches(check.re, text)) {
          if (check.guard && !check.guard(m, text)) continue;
          const { line, text: lineText } = lineOf(text, m.index);
          if (seen.has(line)) continue;
          seen.add(line);
          const rule = RULES.find((r) => r.id === check.ruleId)!;
          out.push({
            ruleId: check.ruleId,
            title: check.title,
            description: check.describe(file, line, m),
            severity: check.severity ?? rule.severity,
            confidence: rule.confidence,
            evidence: `${m[0].trim().slice(0, 160)} at ${file}:${line}`,
            exploit: check.exploit,
            remediation: {
              summary: check.steps[0],
              steps: check.steps,
              codeFix: check.fixAfter,
            },
            mappings: rule.mappings,
            tags: ["iac", basename(file).toLowerCase().includes("dockerfile") ? "docker" : "cloud"],
            location: { file, startLine: line, endLine: line, snippet: safeSnippet(lineText) },
          });
        }
      }
    }
    return out;
  },
};
