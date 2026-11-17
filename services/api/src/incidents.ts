import { getDb, incidents, alerts, incidentAlerts, events, approvals, appendLedger, readLedger } from "@avekshak/db";
import { randomUUID } from "node:crypto";
import { eq, and, desc } from "drizzle-orm";
import type { Alert, NormalizedEvent, Incident, LedgerEntry, Verdict, Approval } from "@avekshak/schema";
import { planResponse, type ResponsePlan } from "./response.js";

/** Thrown when a requested incident does not exist. */
export class IncidentNotFoundError extends Error {
  constructor(incidentId: string) {
    super(`incident not found: ${incidentId}`);
    this.name = "IncidentNotFoundError";
  }
}

/**
 * Thrown when a decision is attempted on an incident that is not in `triaged`
 * state — e.g. a second approve, or approving something the agent hasn't
 * triaged yet. The human gate only opens once, on a triaged incident.
 */
export class InvalidDecisionStateError extends Error {
  constructor(
    incidentId: string,
    readonly currentStatus: string,
  ) {
    super(`incident ${incidentId} is '${currentStatus}', not 'triaged'; cannot decide`);
    this.name = "InvalidDecisionStateError";
  }
}

/** One row in the incident list: the header fields only, no linked detail. */
export interface IncidentSummary extends Incident {}

/** Full incident detail: header + linked alerts + their events + the ledger. */
export interface IncidentDetail extends Incident {
  alerts: Alert[];
  events: NormalizedEvent[];
  ledger: LedgerEntry[];
}

function toIncident(r: typeof incidents.$inferSelect): Incident {
  return {
    id: r.id,
    title: r.title,
    status: r.status as Incident["status"],
    severity: r.severity,
    correlationKey: r.correlationKey,
    verdict: (r.verdict as Verdict | null) ?? null,
    createdAt: (r.createdAt as Date).toISOString(),
    updatedAt: (r.updatedAt as Date).toISOString(),
  };
}

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

function toEvent(r: typeof events.$inferSelect): NormalizedEvent {
  return {
    id: r.id,
    ts: (r.ts as Date).toISOString(),
    source: r.source as NormalizedEvent["source"],
    category: r.category,
    action: r.action,
    outcome: r.outcome as NormalizedEvent["outcome"],
    severity: r.severity,
    actor: { user: r.actorUser ?? undefined, ip: r.actorIp ?? undefined },
    target: {
      host: r.targetHost ?? undefined,
      resource: r.targetResource ?? undefined,
      ip: r.targetIp ?? undefined,
    },
    location:
      r.locationCountry || r.locationCity
        ? { country: r.locationCountry ?? undefined, city: r.locationCity ?? undefined }
        : undefined,
    raw: r.raw as Record<string, unknown>,
  };
}

/** List all incidents, most severe first (ties broken by most-recent update). */
export async function listIncidents(): Promise<IncidentSummary[]> {
  const rows = await getDb()
    .select()
    .from(incidents)
    .orderBy(desc(incidents.severity), desc(incidents.updatedAt));
  return rows.map(toIncident);
}

/** Fetch one incident with its linked alerts, their events, and the full ledger. */
export async function getIncidentDetail(incidentId: string): Promise<IncidentDetail> {
  const db = getDb();

  const incRows = await db
    .select()
    .from(incidents)
    .where(eq(incidents.id, incidentId))
    .limit(1);
  if (incRows.length === 0) throw new IncidentNotFoundError(incidentId);

  const alertRows = await db
    .select()
    .from(alerts)
    .innerJoin(incidentAlerts, eq(incidentAlerts.alertId, alerts.id))
    .where(eq(incidentAlerts.incidentId, incidentId));
  const linkedAlerts = alertRows.map((row) => toAlert(row.alerts));

  const eventIds = [...new Set(linkedAlerts.map((a) => a.eventId))];
  const linkedEvents: NormalizedEvent[] = [];
  for (const eid of eventIds) {
    const evRows = await db.select().from(events).where(eq(events.id, eid)).limit(1);
    if (evRows.length > 0) linkedEvents.push(toEvent(evRows[0]));
  }

  const ledger = await readLedger(incidentId);

  return { ...toIncident(incRows[0]), alerts: linkedAlerts, events: linkedEvents, ledger };
}

/** A recorded human decision plus the incident's new status. */
export interface DecisionResult {
  approval: Approval;
  incidentId: string;
  status: "approved" | "rejected";
  /** The dry-run action, present only when the decision was `approved`. */
  response: ResponsePlan | null;
}

/**
 * Record a human approve/reject on a triaged incident. This is the product's
 * human gate: nothing downstream runs until a person decides here. The decision
 * is only valid from `triaged` — a guarded status update detects a missing or
 * already-decided incident so a double-approve cannot slip through.
 *
 * Writes the incident's new status, an `approvals` row, and a `human.decision`
 * ledger entry. On `approved` only, it then runs the (dry-run) response and
 * records `response.executed`; a rejection never triggers a response — that
 * asymmetry is the whole point of the gate.
 */
export async function decideIncident(
  incidentId: string,
  decision: "approved" | "rejected",
  decidedBy: string,
  note?: string,
): Promise<DecisionResult> {
  const db = getDb();

  // Guarded transition: only flip a currently-`triaged` incident. The RETURNING
  // tells us whether we actually changed a row, and hands back the fields the
  // response planner needs without a second read.
  const updated = await db
    .update(incidents)
    .set({ status: decision, updatedAt: new Date() })
    .where(and(eq(incidents.id, incidentId), eq(incidents.status, "triaged")))
    .returning();

  if (updated.length === 0) {
    // Either the incident doesn't exist or it wasn't triaged. Distinguish the two.
    const rows = await db
      .select({ status: incidents.status })
      .from(incidents)
      .where(eq(incidents.id, incidentId))
      .limit(1);
    if (rows.length === 0) throw new IncidentNotFoundError(incidentId);
    throw new InvalidDecisionStateError(incidentId, rows[0].status);
  }

  const id = randomUUID();
  const decidedAt = new Date();
  await db.insert(approvals).values({
    id,
    incidentId,
    decision,
    decidedBy,
    decidedAt,
    note: note ?? null,
  });

  await appendLedger(incidentId, "human", "human.decision", {
    decision,
    decidedBy,
    note: note ?? null,
  });

  // The human gate: a response only ever runs on approval. Rejection stops here.
  let response: ResponsePlan | null = null;
  if (decision === "approved") {
    response = planResponse(toIncident(updated[0]));
    await appendLedger(incidentId, "system", "response.executed", {
      dryRun: response.dryRun,
      action: response.action,
      target: response.target,
      detail: response.detail,
    });
  }

  const approval: Approval = {
    id,
    incidentId,
    decision,
    decidedBy,
    decidedAt: decidedAt.toISOString(),
    note,
  };
  return { approval, incidentId, status: decision, response };
}
