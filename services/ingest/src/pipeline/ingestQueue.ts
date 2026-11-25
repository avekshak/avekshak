import {
  createQueue,
  createWorker,
  type TypedQueue,
  type Worker,
} from "@avekshak/queue";
import type { NormalizedEvent } from "@avekshak/schema";
import { writeEvent } from "./writeEvent.js";

export const INGEST_QUEUE = "ingest";

/** Downstream detection queue fusion consumes. Named here to avoid an
 * ingest→fusion import cycle; fusion references the same string. */
export const DETECT_QUEUE = "detect";

/** Producer handle connectors use to enqueue normalized events. */
export function ingestQueue(): TypedQueue<NormalizedEvent> {
  return createQueue<NormalizedEvent>(INGEST_QUEUE);
}

/**
 * Consumer: pulls normalized events off the ingest queue, persists them, then
 * forwards the persisted event to the detect queue for the fusion stage. One
 * worker backs all three connectors — they only ever enqueue.
 */
export function startIngestWorker(): Worker<NormalizedEvent> {
  const detect = createQueue<NormalizedEvent>(DETECT_QUEUE);
  return createWorker<NormalizedEvent>(INGEST_QUEUE, async (job) => {
    await writeEvent(job.data);
    await detect.enqueue("event", job.data);
  });
}
