import { homedir } from "node:os";
import { join } from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";

/**
 * Configuration and the model-provider record.
 *
 * Design constraint that shapes this whole file: Guardian-Unit-Penetration-Testing Agent must be fully useful
 * with NO configuration and NO model. Everything here is optional. The
 * deterministic scanners never read this file.
 *
 * API keys are read from the environment or the OS keychain, never written into
 * config. A security product that stores your Anthropic key in a world-readable
 * JSON file has failed at the first hurdle.
 */

export type ProviderKind = "none" | "ollama" | "anthropic" | "openai" | "azure-openai" | "bedrock" | "custom";

export interface ProviderConfig {
  kind: ProviderKind;
  /** Model identifier, e.g. "claude-opus-5", "qwen2.5-coder:14b". */
  model?: string;
  /** Base URL for local or self-hosted inference (Ollama, vLLM, LM Studio). */
  baseUrl?: string;
  /** Name of the environment variable holding the key. Never the key itself. */
  apiKeyEnv?: string;
  /** Rough capability tier, used to decide which agent workflows are safe to run. */
  tier?: "frontier" | "mid" | "small";
}

export interface GuardianUnitConfig {
  version: 1;
  provider: ProviderConfig;
  /** Outbound network is off unless explicitly enabled. Air-gap is the default posture. */
  allowNetwork: boolean;
  /** Telemetry is off and there is no code path that turns it on remotely. */
  telemetry: false;
  /** Directory holding the agent markdown definitions. */
  agentsDir?: string;
  /** Rule ids the org has decided to ignore, with a reason. */
  suppressions: { ruleId: string; path?: string; reason: string; addedAt: string }[];
  /** Severity at or above which `guardian-unit scan --ci` exits non-zero. */
  failOn: "critical" | "high" | "medium" | "low" | "never";
}

export const DEFAULT_CONFIG: GuardianUnitConfig = {
  version: 1,
  provider: { kind: "none" },
  allowNetwork: false,
  telemetry: false,
  suppressions: [],
  failOn: "high",
};

export function configDir(): string {
  return process.env.GUARDIAN_UNIT_HOME ?? join(homedir(), ".guardian-unit");
}

export function configPath(): string {
  return join(configDir(), "config.json");
}

export async function loadConfig(): Promise<GuardianUnitConfig> {
  try {
    const raw = await readFile(configPath(), "utf8");
    const parsed = JSON.parse(raw) as Partial<GuardianUnitConfig>;
    return {
      ...DEFAULT_CONFIG,
      ...parsed,
      telemetry: false,
      provider: { ...DEFAULT_CONFIG.provider, ...parsed.provider },
      suppressions: parsed.suppressions ?? [],
    };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

export async function saveConfig(cfg: GuardianUnitConfig): Promise<void> {
  await mkdir(configDir(), { recursive: true });
  const safe: GuardianUnitConfig = { ...cfg, telemetry: false };
  await writeFile(configPath(), `${JSON.stringify(safe, null, 2)}\n`, { mode: 0o600 });
}

/**
 * Resolve the API key for a provider at call time, from the environment only.
 * Returns null when absent, which is a normal state, not an error.
 */
export function resolveApiKey(p: ProviderConfig): string | null {
  if (p.kind === "none" || p.kind === "ollama") return null;
  const envName =
    p.apiKeyEnv ??
    ({
      anthropic: "ANTHROPIC_API_KEY",
      openai: "OPENAI_API_KEY",
      "azure-openai": "AZURE_OPENAI_API_KEY",
      bedrock: "AWS_BEARER_TOKEN_BEDROCK",
      custom: "GUARDIAN_UNIT_API_KEY",
    } as Record<string, string>)[p.kind];
  if (!envName) return null;
  return process.env[envName] ?? null;
}

/** Human-readable statement of the current privacy posture, shown in the UI header. */
export function privacyPosture(cfg: GuardianUnitConfig): string {
  if (cfg.provider.kind === "none") {
    return "Fully offline. No model configured, no network calls, nothing leaves this machine.";
  }
  if (cfg.provider.kind === "ollama") {
    return `Fully offline. Agent analysis runs on a local model (${cfg.provider.model ?? "unset"}) at ${cfg.provider.baseUrl ?? "http://localhost:11434"}. Your code does not leave this machine.`;
  }
  return `Agent analysis sends selected code excerpts to ${cfg.provider.kind} using your own API key. Deterministic scanning stays local. Switch the provider to Ollama for a fully offline run.`;
}
