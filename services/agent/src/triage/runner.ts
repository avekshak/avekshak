import { getDb, incidents, appendLedger } from "@avekshak/db";
import { eq } from "drizzle-orm";
import type { Verdict } from "@avekshak/schema";
import type { LlmProvider } from "../llm/provider.js";
import { LlmOutputError } from "../llm/provider.js";
import { gatherIncidentContext } from "./context.js";
import { scoreTriage } from "../score/scoreTriage.js";
import { evidenceTextFor, scoreGroundedness } from "../score/groundedness.js";

export interface TriageResult {
  incidentId: string;
  verdict: Verdict;
}

/** Below this groundedness fraction, a benign verdict citing absent indicators is distrusted. */
const GROUNDEDNESS_FLOOR = 0.6;

/**
 * Investigate ONE incident with the 3-tier verdict procedure (ported from
 * AiSOC), recording every step in the ledger, then persist the verdict and move
 * the incident open → triaged. Takes NO response action — triage only judges; a
 * human approves anything that follows (Phase 5).
 *
 * The three tiers:
 *   1. Deterministic scorer (`scoreTriage`) — always computed, recorded as
 *      `triage.score`. It is the floor and the fallback.
 *   2. LLM (`provider.triage`) — may override the deterministic verdict. If the
 *      call fails/returns junk, we fall back to the tier-1 verdict instead of
 *      throwing, so triage ALWAYS produces an answer (`triage.fallback`).
 *   3. Groundedness gate — if the final verdict is `benign` but its rationale
 *      cites indicators absent from the evidence, demote to `suspicious`
 *      (`triage.gate_demotion`). We gate only the benign direction: a hallucinated
 *      "all clear" is the dangerous mistake.
 */
export async function triageIncident(
  incidentId: string,
  provider: LlmProvider,
): Promise<TriageResult> {
  const ctx = await gatherIncidentContext(incidentId);

  await appendLedger(incidentId, "agent", "triage.context_gathered", {
    provider: provider.name,
    alertCount: ctx.alerts.length,
    eventCount: ctx.events.length,
    ruleIds: [...new Set(ctx.alerts.map((a) => a.ruleId))],
  });

  // Tier 1 — deterministic baseline. Recorded alongside the LLM verdict so any
  // disagreement between the two is auditable.
  const score = scoreTriage(ctx);
  await appendLedger(incidentId, "agent", "triage.score", {
    confidence: score.confidence,
    verdict: score.verdict,
    basis: score.basis,
  });

  // Tier 2 — LLM. Overrides the deterministic verdict on success; on failure we
  // fall back to tier 1 rather than aborting triage.
  let verdict: Verdict;
  try {
    verdict = await provider.triage(ctx);
  } catch (err) {
    await appendLedger(incidentId, "agent", "triage.failed", {
      provider: provider.name,
      error: err instanceof Error ? err.message : String(err),
      rawOutput: err instanceof LlmOutputError ? err.raw : undefined,
    });
    verdict = {
      verdict: score.verdict,
      confidence: score.confidence,
      rationale: `LLM triage unavailable; using deterministic baseline. ${score.basis.join("; ")}`,
      recommendedAction: "Human review (automated triage fell back to the deterministic score)",
    };
    await appendLedger(incidentId, "system", "triage.fallback", {
      provider: provider.name,
      verdict: verdict.verdict,
      confidence: verdict.confidence,
    });
  }

  // Tier 3 — groundedness gate on the benign direction only.
  if (verdict.verdict === "benign") {
    const grounded = scoreGroundedness(verdict.rationale, evidenceTextFor(ctx));
    if (grounded.score < GROUNDEDNESS_FLOOR) {
      await appendLedger(incidentId, "system", "triage.gate_demotion", {
        from: "benign",
        to: "suspicious",
        groundednessScore: grounded.score,
        hallucinated: grounded.hallucinated,
      });
      verdict = {
        ...verdict,
        verdict: "suspicious",
        rationale: `${verdict.rationale} [demoted from benign: rationale cited indicators absent from the evidence (${grounded.hallucinated.join(", ")})]`,
      };
    }
  }

  await appendLedger(incidentId, "agent", "triage.verdict", {
    provider: provider.name,
    verdict: verdict.verdict,
    confidence: verdict.confidence,
    rationale: verdict.rationale,
    recommendedAction: verdict.recommendedAction,
  });

  // Persist the verdict and advance status. We only ever do open → triaged here,
  // so a plain guarded update is enough (the full lifecycle machine lives in the
  // correlation service and governs later transitions).
  const db = getDb();
  await db
    .update(incidents)
    .set({ verdict, status: "triaged", updatedAt: new Date() })
    .where(eq(incidents.id, incidentId));

  await appendLedger(incidentId, "system", "incident.status_changed", {
    from: "open",
    to: "triaged",
  });

  return { incidentId, verdict };
}
