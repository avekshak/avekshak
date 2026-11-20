import Anthropic from "@anthropic-ai/sdk";
import type { Verdict } from "@avekshak/schema";
import { type IncidentContext, type LlmProvider } from "./provider.js";
import { SYSTEM_PROMPT, triageWithRetry } from "./prompt.js";

const DEFAULT_MODEL = "claude-sonnet-4-6";

/**
 * Claude-backed triage provider (the MVP default). The shared triageWithRetry
 * loop parses the JSON verdict and re-asks on malformed output; this class only
 * owns the Anthropic transport.
 */
export class ClaudeProvider implements LlmProvider {
  readonly name = "claude";
  private readonly client: Anthropic;
  private readonly model: string;

  constructor(opts?: { apiKey?: string; model?: string; baseURL?: string }) {
    const apiKey = opts?.apiKey ?? process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      throw new Error(
        "ANTHROPIC_API_KEY is not set (required when LLM_PROVIDER=claude)",
      );
    }
    // Optional custom endpoint — e.g. an LLM proxy (Hyperspace) in front of
    // Anthropic. When unset the SDK talks to api.anthropic.com directly.
    const baseURL = opts?.baseURL ?? process.env.ANTHROPIC_BASE_URL;
    this.client = new Anthropic(baseURL ? { apiKey, baseURL } : { apiKey });
    this.model = opts?.model ?? process.env.CLAUDE_MODEL ?? DEFAULT_MODEL;
  }

  async triage(ctx: IncidentContext): Promise<Verdict> {
    return triageWithRetry(ctx, this.name, async (userPrompt) => {
      const res = await this.client.messages.create({
        model: this.model,
        max_tokens: 1024,
        system: SYSTEM_PROMPT,
        messages: [{ role: "user", content: userPrompt }],
      });
      return res.content
        .filter((b): b is Anthropic.TextBlock => b.type === "text")
        .map((b) => b.text)
        .join("");
    });
  }

  async close(): Promise<void> {
    // Anthropic client holds no long-lived connection to tear down.
  }
}
