import {
  createQueue,
  createWorker,
  type TypedQueue,
  type Worker,
} from "@avekshak/queue";
import type { Alert, NormalizedEvent, Rule } from "@avekshak/schema";
import { evaluate } from "../rules/evaluator.js";
import { promoteAlert } from "./alertWriter.js";
import { WindowCounter } from "./windowCounter.js";

/** Must match ingest's DETECT_QUEUE constant. */
export const DETECT_QUEUE = "detect";

/** Downstream correlation queue. Named here; correlation references the same string. */
export const CORRELATE_QUEUE = "correlate";

export interface DetectResult {
  /** Single-event alerts newly created (deduped). */
  created: number;
  /** Brute-force / windowed alerts newly created. */
  windowed: number;
}

/**
 * Pure-ish core: evaluate one event against the rule set, promote matches, and
 * feed window candidates through the counter. Every newly-created alert is
 * handed to `onAlert` (the worker forwards it to the correlate queue; tests can
 * capture it directly). Deduped promotions are not forwarded.
 */
export async function detectEvent(
  ev: NormalizedEvent,
  rules: Rule[],
  counter: WindowCounter,
  onAlert?: (alert: Alert) => Promise<void>,
): Promise<DetectResult> {
  const { matched, windowCandidates } = evaluate(ev, rules);
  let created = 0;
  let windowed = 0;
  for (const rule of matched) {
    const alert = await promoteAlert(ev, rule);
    if (alert) {
      created += 1;
      await onAlert?.(alert);
    }
  }
  for (const rule of windowCandidates) {
    if (await counter.record(ev, rule)) {
      const alert = await promoteAlert(ev, rule);
      if (alert) {
        windowed += 1;
        await onAlert?.(alert);
      }
    }
  }
  return { created, windowed };
}

/**
 * Start the fusion worker: consume normalized events from the detect queue,
 * turn rule matches into alerts, and forward each new alert to the correlate
 * queue. Rules + counter are injected so the caller owns their lifecycle.
 */
export function startFusionWorker(
  rules: Rule[],
  counter: WindowCounter,
): Worker<NormalizedEvent> {
  const correlate: TypedQueue<Alert> = createQueue<Alert>(CORRELATE_QUEUE);
  return createWorker<NormalizedEvent>(DETECT_QUEUE, async (job) => {
    await detectEvent(job.data, rules, counter, async (alert) => {
      await correlate.enqueue("alert", alert);
    });
  });
}
