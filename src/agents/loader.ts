import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Agent definitions are markdown files with YAML frontmatter, the same format
 * the agency-agents roster uses. Guardian Unit reads them rather than embedding
 * prompts in code, so an organization can add its own reviewer -- with its own
 * standards, its own language, its own threat priorities -- by dropping a file
 * into a directory. That is the extension point.
 */

export interface AgentDefinition {
  /** Machine name derived from the filename. */
  slug: string;
  /** Display name from frontmatter. */
  name: string;
  description: string;
  color?: string;
  emoji?: string;
  /** The full markdown body, used as the agent's operating instructions. */
  body: string;
  /** Absolute path it was loaded from. */
  path: string;
  /** Roughly how much of a context window the body consumes. */
  approxTokens: number;
}

/** Minimal frontmatter reader for the `key: value` subset these files use. */
function parseFrontmatter(text: string): { meta: Record<string, string>; body: string } {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  if (!m) return { meta: {}, body: text };
  const meta: Record<string, string> = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z_][\w-]*)\s*:\s*(.*)$/.exec(line);
    if (!kv) continue;
    meta[kv[1]] = kv[2].trim().replace(/^["']|["']$/g, "");
  }
  return { meta, body: text.slice(m[0].length) };
}

/**
 * Search order for agent definitions:
 *   1. An explicit directory (config or --agents-dir)
 *   2. ~/.guardian-unit/agents
 *   3. The bundled copy shipped with Guardian Unit
 *   4. The sibling security/ directory, when running from a checkout of the
 *      agency-agents repository
 */
export function defaultAgentDirs(explicit?: string): string[] {
  const here = fileURLToPath(new URL(".", import.meta.url));
  const dirs = [
    explicit,
    process.env.GUARDIAN_UNIT_AGENTS_DIR,
    join(process.env.GUARDIAN_UNIT_HOME ?? join(process.env.HOME ?? "", ".guardian-unit"), "agents"),
    resolve(here, "..", "..", "agents"),
    resolve(here, "..", "..", "..", "security"),
  ].filter((d): d is string => Boolean(d));
  return [...new Set(dirs)];
}

export async function loadAgents(explicitDir?: string): Promise<AgentDefinition[]> {
  const seen = new Map<string, AgentDefinition>();

  for (const dir of defaultAgentDirs(explicitDir)) {
    let entries: string[];
    try {
      entries = await readdir(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.endsWith(".md")) continue;
      const path = join(dir, entry);
      let text: string;
      try {
        text = await readFile(path, "utf8");
      } catch {
        continue;
      }
      const { meta, body } = parseFrontmatter(text);
      if (!meta.name) continue;

      const slug = entry.replace(/\.md$/, "");
      if (seen.has(slug)) continue; // earlier directories win

      seen.set(slug, {
        slug,
        name: meta.name,
        description: meta.description ?? "",
        color: meta.color,
        emoji: meta.emoji,
        body: body.trim(),
        path,
        approxTokens: Math.ceil(body.length / 4),
      });
    }
  }

  return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Which agent should review which finding.
 *
 * Deliberately a static routing table rather than a model call: choosing a
 * reviewer is a cheap decision that should not cost a round trip, and a fixed
 * mapping is auditable in a way a model's choice is not.
 */
const ROUTING: { match: RegExp; agents: string[] }[] = [
  { match: /^SECRET-|^CI-HARDCODED|^AIA-MCP-SECRET/, agents: ["security-secrets-credential-engineer", "security-appsec-engineer"] },
  { match: /^AIC-/, agents: ["security-ai-generated-code-auditor", "security-appsec-engineer"] },
  { match: /^AIA-/, agents: ["security-ai-generated-code-auditor", "security-architect"] },
  { match: /^CODE-/, agents: ["security-appsec-engineer", "security-penetration-tester"] },
  { match: /^IAC-/, agents: ["security-cloud-security-architect", "security-architect"] },
  { match: /^DEP-|^CI-/, agents: ["security-senior-secops", "security-appsec-engineer"] },
  { match: /^SURF-/, agents: ["security-penetration-tester", "security-cloud-security-architect"] },
];

export function agentForRule(ruleId: string, available: AgentDefinition[]): AgentDefinition | null {
  for (const route of ROUTING) {
    if (!route.match.test(ruleId)) continue;
    for (const slug of route.agents) {
      const found = available.find((a) => a.slug === slug);
      if (found) return found;
    }
  }
  return (
    available.find((a) => a.slug === "security-appsec-engineer") ??
    available.find((a) => a.slug.startsWith("security-")) ??
    null
  );
}
