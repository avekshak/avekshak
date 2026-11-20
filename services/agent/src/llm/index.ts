import type { LlmProvider } from "./provider.js";
import { ClaudeProvider } from "./claude.js";
import { OllamaProvider } from "./ollama.js";

/**
 * Pick the LLM provider from LLM_PROVIDER (default "claude"). The two backends
 * are interchangeable behind LlmProvider, so the rest of the agent never knows
 * which one is live. Claude is the default (hosted, reliable JSON); Ollama is
 * the local, no-egress opt-in.
 */
export function createProvider(
  name: string = process.env.LLM_PROVIDER ?? "claude",
): LlmProvider {
  switch (name) {
    case "claude":
      return new ClaudeProvider();
    case "ollama":
      return new OllamaProvider();
    default:
      throw new Error(
        `unknown LLM_PROVIDER "${name}" (expected "claude" or "ollama")`,
      );
  }
}

export type { LlmProvider, IncidentContext } from "./provider.js";
export { LlmOutputError } from "./provider.js";
