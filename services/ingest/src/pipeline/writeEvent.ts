import { getDb, events } from "@avekshak/db";
import type { NormalizedEvent } from "@avekshak/schema";

/**
 * Flattens a NormalizedEvent (nested actor/target/location) into the events
 * table's columns and inserts it. The single place connectors funnel into, so
 * the raw→row mapping lives in exactly one spot.
 *
 * Insert is idempotent on the primary key: a repeated event id (e.g. the same
 * Wazuh doc seen on an overlapping poll) is a no-op rather than a duplicate.
 */
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
