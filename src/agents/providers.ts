import type { ProviderConfig } from "../core/config.ts";
import { resolveApiKey } from "../core/config.ts";

function providerHttpError(provider: string, status: number): Error {
  // Never include a provider response body. Those bodies can contain request
  // echoes, credentials, or arbitrary third-party text that later becomes a
  // scan warning, a stored record, or an exported report.
  return new Error(`${provider} returned HTTP ${status}.`);
}

/**
 * Model provider abstraction.
 *
 * Guardian-Unit-Penetration-Testing Agent never ships a model and never proxies inference through a service we
 * operate. The organization supplies the brain: a local model over Ollama or
 * any OpenAI-compatible endpoint, or their own key with a hosted provider. That
 * is what makes "your code never leaves the building" a property of the
 * architecture rather than a promise in a privacy policy.
 */

export interface CompletionRequest {
  system: string;
  /** Untrusted content. Always sent as a user-role message, never merged into `system`. */
  user: string;
  maxTokens?: number;
  temperature?: number;
  signal?: AbortSignal;
}

export interface Provider {
  kind: ProviderConfig["kind"];
  model: string;
  /** Description shown in the UI so the user always knows where their code is going. */
  describe(): string;
  available(): Promise<{ ok: boolean; detail: string }>;
  complete(req: CompletionRequest): Promise<string>;
}

class NullProvider implements Provider {
  kind = "none" as const;
  model = "none";
  describe() {
    return "No model configured. Deterministic scanning only, fully offline.";
  }
  async available() {
    return { ok: false, detail: "No model configured." };
  }
  async complete(): Promise<string> {
    throw new Error("No model provider is configured.");
  }
}

class OllamaProvider implements Provider {
  kind = "ollama" as const;
  model: string;
  private baseUrl: string;
  constructor(model: string, baseUrl: string) {
    this.model = model;
    this.baseUrl = baseUrl;
  }
  describe() {
    return `Local model ${this.model} at ${this.baseUrl}. Nothing leaves this machine.`;
  }
  async available() {
    try {
      const res = await fetch(`${this.baseUrl}/api/tags`, { signal: AbortSignal.timeout(4000) });
      if (!res.ok) return { ok: false, detail: `Ollama responded ${res.status}.` };
      const data = (await res.json()) as { models?: { name: string }[] };
      const names = (data.models ?? []).map((m) => m.name);
      if (names.length === 0) {
        return { ok: false, detail: "Ollama is running but has no models. Try: ollama pull qwen2.5-coder:14b" };
      }
      const has = names.some((n) => n === this.model || n.startsWith(`${this.model}:`));
      return has
        ? { ok: true, detail: `Ollama is running with ${this.model}.` }
        : { ok: false, detail: `Ollama is running but ${this.model} is not installed. Available: ${names.slice(0, 5).join(", ")}` };
    } catch {
      return { ok: false, detail: `Could not reach Ollama at ${this.baseUrl}. Start it with: ollama serve` };
    }
  }
  async complete(req: CompletionRequest): Promise<string> {
    const res = await fetch(`${this.baseUrl}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: this.model,
        stream: false,
        options: { temperature: req.temperature ?? 0, num_predict: req.maxTokens ?? 1024 },
        messages: [
          { role: "system", content: req.system },
          { role: "user", content: req.user },
        ],
      }),
      signal: req.signal,
    });
    if (!res.ok) throw providerHttpError("Ollama", res.status);
    const data = (await res.json()) as { message?: { content?: string } };
    return data.message?.content ?? "";
  }
}

class AnthropicProvider implements Provider {
  kind = "anthropic" as const;
  model: string;
  private apiKey: string;
  constructor(model: string, apiKey: string) {
    this.model = model;
    this.apiKey = apiKey;
  }
  describe() {
    return `Anthropic ${this.model}, called with your own API key. Selected code excerpts are sent to Anthropic; deterministic scanning stays local.`;
  }
  async available() {
    return this.apiKey
      ? { ok: true, detail: `Using your ANTHROPIC_API_KEY with ${this.model}.` }
      : { ok: false, detail: "ANTHROPIC_API_KEY is not set in this environment." };
  }
  async complete(req: CompletionRequest): Promise<string> {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": this.apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: req.maxTokens ?? 1024,
        temperature: req.temperature ?? 0,
        system: req.system,
        messages: [{ role: "user", content: req.user }],
      }),
      signal: req.signal,
    });
    if (!res.ok) throw providerHttpError("Anthropic API", res.status);
    const data = (await res.json()) as { content?: { type: string; text?: string }[] };
    return (data.content ?? []).filter((c) => c.type === "text").map((c) => c.text ?? "").join("");
  }
}

class OpenAICompatibleProvider implements Provider {
  kind: ProviderConfig["kind"];
  model: string;
  private baseUrl: string;
  private apiKey: string | null;
  constructor(
    kind: ProviderConfig["kind"],
    model: string,
    baseUrl: string,
    apiKey: string | null,
  ) {
    this.kind = kind;
    this.model = model;
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }
  describe() {
    const local = /localhost|127\.0\.0\.1|::1/.test(this.baseUrl);
    return local
      ? `Local model ${this.model} at ${this.baseUrl}. Nothing leaves this machine.`
      : `${this.model} at ${this.baseUrl}, called with your own credentials.`;
  }
  async available() {
    if (!this.apiKey && !/localhost|127\.0\.0\.1|::1/.test(this.baseUrl)) {
      return { ok: false, detail: "No API key found in the environment for this provider." };
    }
    return { ok: true, detail: `Configured for ${this.model} at ${this.baseUrl}.` };
  }
  async complete(req: CompletionRequest): Promise<string> {
    const res = await fetch(`${this.baseUrl.replace(/\/$/, "")}/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {}),
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: req.maxTokens ?? 1024,
        temperature: req.temperature ?? 0,
        messages: [
          { role: "system", content: req.system },
          { role: "user", content: req.user },
        ],
      }),
      signal: req.signal,
    });
    if (!res.ok) throw providerHttpError("Provider", res.status);
    const data = (await res.json()) as { choices?: { message?: { content?: string } }[] };
    return data.choices?.[0]?.message?.content ?? "";
  }
}

export function makeProvider(cfg: ProviderConfig): Provider {
  const key = resolveApiKey(cfg);
  switch (cfg.kind) {
    case "ollama":
      return new OllamaProvider(cfg.model ?? "qwen2.5-coder:14b", cfg.baseUrl ?? "http://localhost:11434");
    case "anthropic":
      return key
        ? new AnthropicProvider(cfg.model ?? "claude-sonnet-5", key)
        : new NullProvider();
    case "openai":
      return new OpenAICompatibleProvider("openai", cfg.model ?? "gpt-5", cfg.baseUrl ?? "https://api.openai.com/v1", key);
    case "azure-openai":
    case "bedrock":
    case "custom":
      return cfg.baseUrl
        ? new OpenAICompatibleProvider(cfg.kind, cfg.model ?? "default", cfg.baseUrl, key)
        : new NullProvider();
    default:
      return new NullProvider();
  }
}

/**
 * Capability tier drives how much we ask of the model. A 7B local model can
 * usefully answer "is this finding real, yes or no, and why in one paragraph".
 * It cannot usefully perform open-ended architectural review, and pretending
 * otherwise produces confident nonsense in a security report.
 */
export function tierOf(cfg: ProviderConfig): "frontier" | "mid" | "small" {
  if (cfg.tier) return cfg.tier;
  const m = (cfg.model ?? "").toLowerCase();
  if (/opus|gpt-5|sonnet-5|gemini-3-pro|o[34]\b/.test(m)) return "frontier";
  if (/sonnet|gpt-4|haiku|mistral-large|command-r-plus|70b|72b|32b/.test(m)) return "mid";
  return "small";
}
