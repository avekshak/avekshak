import type { Verdict } from "@avekshak/schema";
import { type IncidentContext, type LlmProvider } from "./provider.js";
import { SYSTEM_PROMPT, triageWithRetry } from "./prompt.js";

const DEFAULT_URL = "http://localhost:11434";
const DEFAULT_MODEL = "llama3.2:3b";

interface OllamaChatResponse {
  message?: { content?: string };
}

/**
 * Ollama-backed triage provider (opt-in, LLM_PROVIDER=ollama). Talks to a local
 * Ollama server's /api/chat over HTTP. `format: "json"` asks the runtime to
 * constrain output to JSON; the shared retry loop still parses defensively since
 * small local models drift. No egress — everything stays on the host.
 */
export class OllamaProvider implements LlmProvider {
  readonly name = "ollama";
  private readonly baseUrl: string;
  private readonly model: string;

  constructor(opts?: { url?: string; model?: string }) {
    this.baseUrl = (opts?.url ?? process.env.OLLAMA_URL ?? DEFAULT_URL).replace(
      /\/$/,
      "",
    );
    this.model = opts?.model ?? process.env.OLLAMA_MODEL ?? DEFAULT_MODEL;
  }

  async triage(ctx: IncidentContext): Promise<Verdict> {
    return triageWithRetry(ctx, this.name, async (userPrompt) => {
      const res = await fetch(`${this.baseUrl}/api/chat`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: this.model,
          stream: false,
          format: "json",
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: userPrompt },
          ],
        }),
      });
      if (!res.ok) {
        throw new Error(
          `Ollama request failed: ${res.status} ${res.statusText}`,
        );
      }
      const body = (await res.json()) as OllamaChatResponse;
      return body.message?.content ?? "";
    });
  }

  async close(): Promise<void> {
    // Stateless HTTP client; nothing to close.
  }
}
