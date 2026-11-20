import type { IncidentContext } from "../llm/provider.js";
import { buildUserPrompt } from "../llm/prompt.js";

/**
 * Tier 3 of the verdict procedure (ported from AiSOC's groundedness.py).
 *
 * A blind, deterministic honesty axis: what fraction of the concrete indicators
 * the LLM asserts in its rationale actually appear in the evidence it was shown?
 * An indicator in the output that is absent from the evidence is a hallucination.
 *
 * We use it in the runner to gate the benign direction only: if the model says
 * "benign" but cites IOCs the evidence never contained, we don't trust the
 * benign call and demote it. Regex extraction, no LLM in the loop.
 */

/**
 * Concrete, checkable indicators. Deliberately narrow — we only score things
 * that must be traceable to evidence, not prose.
 */
const PATTERNS: Record<string, RegExp> = {
  ipv4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  md5: /\b[a-fA-F0-9]{32}\b/g,
  cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
  mitre: /\bT\d{4}(?:\.\d{3})?\b/g,
  domain: /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi,
};

/** Domains that are structural noise, not claimed indicators. */
const DOMAIN_STOPWORDS = new Set(["e.g", "i.e", "etc.al"]);

export interface GroundednessResult {
  /** 1.0 = every claimed indicator is grounded in evidence. */
  score: number;
  grounded: string[];
  hallucinated: string[];
}

function extract(text: string): Set<string> {
  const found = new Set<string>();
  for (const [kind, pattern] of Object.entries(PATTERNS)) {
    const matchesFound = (text || "").match(pattern) ?? [];
    for (const m of matchesFound) {
      const token = m.toLowerCase();
      if (kind === "domain" && (DOMAIN_STOPWORDS.has(token) || !token.includes("."))) {
        continue;
      }
      found.add(token);
    }
  }
  return found;
}

/**
 * Fraction of the output's concrete indicators that appear in the evidence.
 * No indicators claimed => perfectly grounded (1.0): the agent didn't assert
 * any checkable fact to hallucinate.
 */
export function scoreGroundedness(
  outputText: string,
  evidenceText: string,
): GroundednessResult {
  const claimed = extract(outputText);
  if (claimed.size === 0) {
    return { score: 1, grounded: [], hallucinated: [] };
  }
  const evidence = extract(evidenceText);
  const grounded: string[] = [];
  const hallucinated: string[] = [];
  for (const token of claimed) {
    if (evidence.has(token)) grounded.push(token);
    else hallucinated.push(token);
  }
  grounded.sort();
  hallucinated.sort();
  const score = Math.round((grounded.length / claimed.size) * 10000) / 10000;
  return { score, grounded, hallucinated };
}

/**
 * The evidence text to check a rationale against: EXACTLY what the model was
 * shown. We reuse `buildUserPrompt` so the gate can never credit or fault the
 * model for a fact that wasn't in its prompt (e.g. the dropped `raw` blob).
 */
export function evidenceTextFor(ctx: IncidentContext): string {
  return buildUserPrompt(ctx);
}
