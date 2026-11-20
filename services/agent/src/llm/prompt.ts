import { VerdictSchema, type Verdict } from "@avekshak/schema";
import type { IncidentContext } from "./provider.js";
import { LlmOutputError } from "./provider.js";

/**
 * System prompt: fixes the agent's role and — critically — the exact JSON
 * contract. We ask for JSON only so the output is machine-parseable; the parser
 * still tolerates a model that wraps it in prose or a ```json fence.
 */
export const SYSTEM_PROMPT = `You are a SOC (Security Operations Center) triage analyst.
You are given ONE security incident: a correlation of related alerts and the raw events behind them.
Judge the incident and respond with a single JSON object, and nothing else.

The JSON object MUST have exactly these keys:
- "verdict": one of "benign", "suspicious", "critical"
- "confidence": a number 0-100 (your confidence in the verdict)
- "rationale": a short string explaining WHY, grounded in the specific alerts/events
- "recommendedAction": a short string naming the single next action a human should consider

Guidance:
- "benign" = expected/legitimate activity (e.g. a known user's own login, even at an odd hour or from travel).
- "suspicious" = anomalous and worth a human look, but not clearly an active compromise.
- "critical" = strong signal of an active attack or data loss (e.g. data exfiltration, confirmed unauthorized access).
Do NOT recommend or take any automated action yourself — a human approves everything. Output JSON only.`;

/** Compact one alert to the fields that matter for judgment. */
function describeAlert(a: IncidentContext["alerts"][number]): Record<string, unknown> {
  return {
    rule: a.ruleId,
    title: a.title,
    severity: a.severity,
    ts: a.ts,
    actorIp: a.actorIp ?? null,
    actorUser: a.actorUser ?? null,
    targetHost: a.targetHost ?? null,
  };
}

/** Compact one event — keep the signal fields, drop the untouched vendor blob. */
function describeEvent(e: IncidentContext["events"][number]): Record<string, unknown> {
  return {
    ts: e.ts,
    source: e.source,
    category: e.category,
    action: e.action,
    outcome: e.outcome,
    severity: e.severity,
    actor: e.actor,
    target: e.target,
    location: e.location ?? null,
  };
}

/**
 * Pure: build the user message describing the incident. Deterministic given the
 * context, so a unit test can assert the structure without a live model.
 */
export function buildUserPrompt(ctx: IncidentContext): string {
  const payload = {
    incident: {
      id: ctx.incidentId,
      title: ctx.title,
      currentSeverity: ctx.severity,
      correlationKey: ctx.correlationKey,
      openedAt: ctx.createdAt,
      alertCount: ctx.alerts.length,
      eventCount: ctx.events.length,
    },
    alerts: ctx.alerts.map(describeAlert),
    events: ctx.events.map(describeEvent),
  };
  return `Here is the incident to triage:\n\n${JSON.stringify(payload, null, 2)}\n\nRespond with the JSON verdict object only.`;
}

/**
 * Pull the first balanced JSON object out of arbitrary model text. Handles a
 * bare object, a ```json fenced block, or an object embedded in prose. Returns
 * null if no plausible object is present.
 */
export function extractJsonObject(text: string): string | null {
  const start = text.indexOf("{");
  if (start === -1) return null;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}

/**
 * Pure: parse + validate raw model text into a Verdict. Returns null on any
 * failure (no JSON, bad JSON, or schema violation) so the caller can retry.
 * Never throws — retry logic lives in the provider/worker.
 */
export function parseVerdict(raw: string): Verdict | null {
  const json = extractJsonObject(raw);
  if (json === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  const result = VerdictSchema.safeParse(parsed);
  return result.success ? result.data : null;
}

/** Default number of times a provider re-asks the model for valid JSON. */
export const MAX_ATTEMPTS = 3;

/**
 * Shared retry loop for every provider. `callModel(userPrompt, attempt)` does
 * the one transport-specific thing — send the prompt, return the raw text. We
 * parse+validate here and, on failure, re-ask with a correction nudge. After
 * MAX_ATTEMPTS bad outputs we throw LlmOutputError (handled upstream, never a
 * crash). Keeping this transport-agnostic makes the retry behavior unit-testable
 * with a fake callModel.
 */
export async function triageWithRetry(
  ctx: IncidentContext,
  providerName: string,
  callModel: (userPrompt: string, attempt: number) => Promise<string>,
  maxAttempts = MAX_ATTEMPTS,
): Promise<Verdict> {
  const base = buildUserPrompt(ctx);
  let lastRaw = "";
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const userPrompt =
      attempt === 1
        ? base
        : `${base}\n\nYour previous reply could not be parsed as the required JSON object. Reply again with ONLY the JSON object.`;
    lastRaw = await callModel(userPrompt, attempt);
    const verdict = parseVerdict(lastRaw);
    if (verdict) return verdict;
  }
  throw new LlmOutputError(
    `${providerName} did not return a valid Verdict after ${maxAttempts} attempts`,
    lastRaw,
  );
}
