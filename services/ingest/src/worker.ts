import { createWorker, createQueue } from "@avekshak/queue";
import { getDb, events } from "@avekshak/db";
import { NormalizedEventSchema } from "@avekshak/schema";
import type { NormalizedEvent } from "@avekshak/schema";

const db = getDb();
const detectQueue = createQueue<NormalizedEvent>("detect");

export function startIngestWorker(): void {
  createWorker<NormalizedEvent>("ingest", async (job) => {
    const parsed = NormalizedEventSchema.safeParse(job.data);
    if (!parsed.success) {
      console.error("[ingest:worker] invalid event schema:", parsed.error.flatten());
      return;
    }

    const e = parsed.data;
    await db
      .insert(events)
      .values({
        id: e.id,
        ts: new Date(e.ts),
        source: e.source,
        category: e.category,
        action: e.action,
        outcome: e.outcome,
        severity: e.severity,
        actorUser: e.actor.user ?? null,
        actorIp: e.actor.ip ?? null,
        targetHost: e.target.host ?? null,
        targetResource: e.target.resource ?? null,
        targetIp: e.target.ip ?? null,
        locationCountry: e.location?.country ?? null,
        locationCity: e.location?.city ?? null,
        raw: e.raw,
      })
      .onConflictDoNothing();

    await detectQueue.enqueue("event", e);
    console.log(`[ingest:worker] wrote event ${e.id} source=${e.source} action=${e.action}`);
  });

  console.log("[ingest:worker] started");
}
