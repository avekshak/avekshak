import { getDb, incidents } from "@avekshak/db";
import { eq } from "drizzle-orm";
import type { IncidentStatusType } from "@avekshak/schema";

/**
 * Allowed incident status transitions. The lifecycle is deliberately linear
 * with one branch: open → triaged → (approved | rejected) → closed. A closed
 * incident is terminal. Enforced centrally so no stage can shove an incident
 * into an illegal state (e.g. approving something never triaged).
 */
const TRANSITIONS: Record<IncidentStatusType, IncidentStatusType[]> = {
  open: ["triaged"],
  triaged: ["approved", "rejected"],
  approved: ["closed"],
  rejected: ["closed"],
  closed: [],
};

export class InvalidTransitionError extends Error {
  constructor(from: IncidentStatusType, to: IncidentStatusType) {
    super(`illegal incident transition: ${from} → ${to}`);
    this.name = "InvalidTransitionError";
  }
}

export function canTransition(
  from: IncidentStatusType,
  to: IncidentStatusType,
): boolean {
  return TRANSITIONS[from].includes(to);
}

/**
 * Transition an incident to a new status, enforcing the lifecycle. Throws
 * InvalidTransitionError on an illegal move and NotFound if the incident is
 * missing. Returns the new status.
 */
export async function transitionIncident(
  incidentId: string,
  to: IncidentStatusType,
): Promise<IncidentStatusType> {
  const db = getDb();
  const rows = await db
    .select({ status: incidents.status })
    .from(incidents)
    .where(eq(incidents.id, incidentId))
    .limit(1);
  if (rows.length === 0) {
    throw new Error(`incident not found: ${incidentId}`);
  }
  const from = rows[0].status as IncidentStatusType;
  if (from === to) return from; // no-op, idempotent
  if (!canTransition(from, to)) {
    throw new InvalidTransitionError(from, to);
  }
  await db
    .update(incidents)
    .set({ status: to, updatedAt: new Date() })
    .where(eq(incidents.id, incidentId));
  return to;
}
