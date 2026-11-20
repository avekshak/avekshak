import { getDb, events } from "@avekshak/db";
import type { NormalizedEvent } from "@avekshak/schema";

export async function writeEvent(ev: NormalizedEvent): Promise<void> {
  await getDb()
    .insert(events)
    .values({
      id: ev.id,
      ts: new Date(ev.ts),
      source: ev.source,
      category: ev.category,
      action: ev.action,
      outcome: ev.outcome,
      severity: ev.severity,
      actorUser: ev.actor.user ?? null,
      actorIp: ev.actor.ip ?? null,
      targetHost: ev.target.host ?? null,
      targetResource: ev.target.resource ?? null,
      targetIp: ev.target.ip ?? null,
      locationCountry: ev.location?.country ?? null,
      locationCity: ev.location?.city ?? null,
      raw: ev.raw,
    })
    .onConflictDoNothing({ target: events.id });
}
