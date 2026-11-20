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

export function ingestQueue(): TypedQueue<NormalizedEvent> {
  return createQueue<NormalizedEvent>(INGEST_QUEUE);
}

export function startIngestWorker(): Worker<NormalizedEvent> {
  const detect = createQueue<NormalizedEvent>(DETECT_QUEUE);
  return createWorker<NormalizedEvent>(INGEST_QUEUE, async (job) => {
    await writeEvent(job.data);
    await detect.enqueue("event", job.data);
  });
}
