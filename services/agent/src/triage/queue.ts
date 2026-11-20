import { createQueue, createWorker, type Worker, type TypedQueue } from "@avekshak/queue";
import type { LlmProvider } from "../llm/provider.js";
import { triageIncident } from "./runner.js";

/** Payload on the triage queue: just the incident to investigate. */
export interface TriageJob {
  incidentId: string;
}

/** Queue name — correlation enqueues here when it opens a new incident. */
export const TRIAGE_QUEUE = "triage";

export function triageQueue(): TypedQueue<TriageJob> {
  return createQueue<TriageJob>(TRIAGE_QUEUE);
}

/**
 * Start the triage worker: consume incidents and investigate each with the
 * injected LLM provider. The provider's lifecycle is owned by the caller.
 */
export function startTriageWorker(provider: LlmProvider): Worker<TriageJob> {
  return createWorker<TriageJob>(TRIAGE_QUEUE, async (job) => {
    await triageIncident(job.data.incidentId, provider);
  });
}
