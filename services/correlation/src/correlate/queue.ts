import { createQueue, createWorker, type TypedQueue, type Worker } from "@avekshak/queue";
import type { Alert } from "@avekshak/schema";
import { Correlator } from "./correlator.js";

/** Must match fusion's CORRELATE_QUEUE constant. */
export const CORRELATE_QUEUE = "correlate";

/**
 * Downstream triage queue (consumed by services/agent). Named here as a plain
 * string so correlation needn't depend on the agent package — keeping the
 * build acyclic. Must match agent's TRIAGE_QUEUE.
 */
export const TRIAGE_QUEUE = "triage";

interface TriageJob {
  incidentId: string;
}

/**
 * Start the correlation worker: consume alerts from the correlate queue and
 * group each into an incident. When an alert opens a BRAND-NEW incident, forward
 * it to the triage queue so the agent investigates it exactly once. The
 * Correlator is injected so the caller owns its (Redis) lifecycle.
 */
export function startCorrelationWorker(correlator: Correlator): Worker<Alert> {
  const triage: TypedQueue<TriageJob> = createQueue<TriageJob>(TRIAGE_QUEUE);
  return createWorker<Alert>(CORRELATE_QUEUE, async (job) => {
    const result = await correlator.correlate(job.data);
    if (result.createdIncident) {
      await triage.enqueue("incident", { incidentId: result.incidentId });
    }
  });
}
