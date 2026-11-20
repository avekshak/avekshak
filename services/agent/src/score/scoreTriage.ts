import type { Verdict } from "@avekshak/schema";
import type { IncidentContext } from "../llm/provider.js";
import {
  CRITICAL_KEYWORDS,
  HIGH_KEYWORDS,
  anyMatched,
  normalise,
} from "./keywords.js";

/**
 * Tier 1 of the 3-tier verdict procedure (ported from AiSOC's score_triage).
 *
 * A pure, deterministic evidence-weight stack that produces a verdict WITHOUT
 * the LLM. It is the source-of-truth floor and the fallback: the triage runner
 * always computes it, records it in the ledger, and — if the LLM call fails —
 * persists this instead of throwing. An LLM/score disagreement stays auditable
 * because both are written down.
 *
 * This is NOT a probability. It's a calibrated evidence count squashed into
 * [0.05, 0.95], then banded into our frozen Verdict enum.
 */

const CONF_FLOOR = 0.05;
const CONF_CEIL = 0.95;

function clamp(v: number): number {
  return Math.max(CONF_FLOOR, Math.min(CONF_CEIL, v));
}

export interface TriageScore {
  /** 0–100, matching our Verdict.confidence scale. */
  confidence: number;
  verdict: Verdict["verdict"];
  /** Human-readable bullets explaining each contribution. */
  basis: string[];
}

/**
 * Build the keyword haystack from exactly the text the LLM is shown: alert
 * titles plus each event's action + category. We deliberately do NOT read the
 * `raw` vendor blob — `buildUserPrompt` drops it, so scoring on it would judge
 * the incident on evidence the model never saw. Opaque identifiers are blanked
 * (the #1607 fix) by `normalise`.
 */
function keywordHaystack(ctx: IncidentContext): string {
  const parts: string[] = [];
  for (const a of ctx.alerts) parts.push(a.title);
  for (const e of ctx.events) {
    parts.push(e.action);
    parts.push(e.category);
  }
  return normalise(parts.join(" "));
}

/**
 * Count distinct IOC anchors present on the incident. More anchors = more for
 * downstream enrichment to pivot on, so it nudges confidence up. Our analog of
 * AiSOC's (src_ip, dst_ip, domain, file_hash, url): the identity/network fields
 * our schema actually carries.
 */
function countIocs(ctx: IncidentContext): number {
  let hits = 0;
  const seenIps = new Set<string>();
  const seenUsers = new Set<string>();
  const seenHosts = new Set<string>();
  const seenResources = new Set<string>();
  for (const e of ctx.events) {
    if (e.actor.ip) seenIps.add(e.actor.ip);
    if (e.target.ip) seenIps.add(e.target.ip);
    if (e.actor.user) seenUsers.add(e.actor.user);
    if (e.target.host) seenHosts.add(e.target.host);
    if (e.target.resource) seenResources.add(e.target.resource);
  }
  for (const a of ctx.alerts) {
    if (a.actorIp) seenIps.add(a.actorIp);
    if (a.actorUser) seenUsers.add(a.actorUser);
    if (a.targetHost) seenHosts.add(a.targetHost);
  }
  if (seenIps.size) hits += 1;
  if (seenUsers.size) hits += 1;
  if (seenHosts.size) hits += 1;
  if (seenResources.size) hits += 1;
  return hits;
}

/** True if any event or alert names a target host — enables containment. */
function hasHost(ctx: IncidentContext): boolean {
  return (
    ctx.events.some((e) => Boolean(e.target.host)) ||
    ctx.alerts.some((a) => Boolean(a.targetHost))
  );
}

/**
 * The max raw severity across the incident's alerts and events, on 0–100 →
 * 0–1. Our analog of AiSOC's vendor `risk_score`. We take the MAX rather than a
 * mean so one high-severity signal in a noisy incident still carries weight.
 */
function maxSeverity(ctx: IncidentContext): number {
  let max = ctx.severity;
  for (const a of ctx.alerts) max = Math.max(max, a.severity);
  for (const e of ctx.events) max = Math.max(max, e.severity);
  return max;
}

/**
 * Pure deterministic triage score. Same input → same output, no I/O.
 *
 * Weight stack (adapted from AiSOC score_triage):
 *   - risk: maxSeverity/100 × 0.6, capped at 0.60
 *   - +0.35 if a critical keyword is in the alert/event text, else +0.20 if high
 *   - +0.05 per distinct IOC field present, capped at 0.15
 *   - +0.05 if a target host is present
 *
 * MITRE technique weighting is omitted on purpose: our schema carries no
 * technique IDs (ATT&CK mapping is post-MVP), so there is nothing to count.
 *
 * Bands → our frozen enum (tuned to our rule severities, not copied blindly):
 *   confidence ≥ 0.60 → critical; 0.35–0.60 → suspicious; < 0.35 → benign.
 */
export function scoreTriage(ctx: IncidentContext): TriageScore {
  const basis: string[] = [];
  let weight = 0;

  const risk = maxSeverity(ctx) / 100;
  if (risk > 0) {
    const contribution = Math.min(risk * 0.6, 0.6);
    basis.push(`max severity ${Math.round(risk * 100)}/100 → +${contribution.toFixed(2)}`);
    weight += contribution;
  }

  const haystack = keywordHaystack(ctx);
  if (anyMatched(haystack, CRITICAL_KEYWORDS)) {
    basis.push("critical-severity keyword in alert/event text → +0.35");
    weight += 0.35;
  } else if (anyMatched(haystack, HIGH_KEYWORDS)) {
    basis.push("high-severity keyword in alert/event text → +0.20");
    weight += 0.2;
  }

  const iocs = countIocs(ctx);
  if (iocs > 0) {
    const contribution = Math.min(iocs * 0.05, 0.15);
    basis.push(`${iocs} IOC field(s) present → +${contribution.toFixed(2)}`);
    weight += contribution;
  }

  if (hasHost(ctx)) {
    basis.push("target host present (enables containment) → +0.05");
    weight += 0.05;
  }

  const confidence01 = clamp(weight);

  let verdict: Verdict["verdict"];
  if (confidence01 >= 0.6) verdict = "critical";
  else if (confidence01 >= 0.35) verdict = "suspicious";
  else verdict = "benign";

  if (basis.length === 0) {
    basis.push("no salient signals — defaulting to floor confidence");
  }

  return {
    confidence: Math.round(confidence01 * 100),
    verdict,
    basis,
  };
}
