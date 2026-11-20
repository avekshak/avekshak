import { getDb, incidents, alerts, incidentAlerts, events } from "@avekshak/db";
import { eq } from "drizzle-orm";
import type { Alert, NormalizedEvent } from "@avekshak/schema";
import type { IncidentContext } from "../llm/provider.js";

/** Thrown when triage is asked to investigate an incident that doesn't exist. */
export class IncidentNotFoundError extends Error {
  constructor(incidentId: string) {
    super(`incident not found: ${incidentId}`);
    this.name = "IncidentNotFoundError";
  }
}

/** Map an alerts row to the Alert schema shape (nullable cols → optional). */
function toAlert(r: typeof alerts.$inferSelect): Alert {
  return {
    id: r.id,
    eventId: r.eventId,
    ruleId: r.ruleId,
    title: r.title,
    severity: r.severity,
    ts: (r.ts as Date).toISOString(),
    actorIp: r.actorIp ?? undefined,
    actorUser: r.actorUser ?? undefined,
    targetHost: r.targetHost ?? undefined,
  };
}

/** Map an events row back to the flat NormalizedEvent envelope. */
function toEvent(r: typeof events.$inferSelect): NormalizedEvent {
  return {
    id: r.id,
    ts: (r.ts as Date).toISOString(),
    source: r.source as NormalizedEvent["source"],
    category: r.category,
    action: r.action,
    outcome: r.outcome as NormalizedEvent["outcome"],
    severity: r.severity,
    actor: {
      user: r.actorUser ?? undefined,
      ip: r.actorIp ?? undefined,
    },
    target: {
      host: r.targetHost ?? undefined,
      resource: r.targetResource ?? undefined,
      ip: r.targetIp ?? undefined,
    },
    location:
      r.locationCountry || r.locationCity
        ? {
            country: r.locationCountry ?? undefined,
            city: r.locationCity ?? undefined,
          }
        : undefined,
    raw: r.raw as Record<string, unknown>,
  };
}

/**
 * Assemble the full triage context for one incident from Postgres: the incident
 * header, every linked alert, and the raw event behind each alert. This is the
 * exact bundle the LLM provider judges — no network, pure DB reads.
 */
export async function gatherIncidentContext(
  incidentId: string,
): Promise<IncidentContext> {
  const db = getDb();

  const incRows = await db
    .select()
    .from(incidents)
    .where(eq(incidents.id, incidentId))
    .limit(1);
  if (incRows.length === 0) throw new IncidentNotFoundError(incidentId);
  const inc = incRows[0];

  const alertRows = await db
    .select()
    .from(alerts)
    .innerJoin(incidentAlerts, eq(incidentAlerts.alertId, alerts.id))
    .where(eq(incidentAlerts.incidentId, incidentId));
  const linkedAlerts = alertRows.map((row) => toAlert(row.alerts));

  const eventIds = [...new Set(linkedAlerts.map((a) => a.eventId))];
  const linkedEvents: NormalizedEvent[] = [];
  for (const eid of eventIds) {
    const evRows = await db
      .select()
      .from(events)
      .where(eq(events.id, eid))
      .limit(1);
    if (evRows.length > 0) linkedEvents.push(toEvent(evRows[0]));
  }

  return {
    incidentId: inc.id,
    title: inc.title,
    severity: inc.severity,
    correlationKey: inc.correlationKey,
    createdAt: (inc.createdAt as Date).toISOString(),
    alerts: linkedAlerts,
    events: linkedEvents,
  };
}
