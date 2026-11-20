import type {
  Incident,
  Alert,
  NormalizedEvent,
  LedgerEntry,
  Approval,
} from "@avekshak/schema";

// Re-export the schema primitives the UI renders directly, so components can
// import everything from one place.
export type { Incident, Alert, NormalizedEvent, LedgerEntry, Approval };

/**
 * Full incident detail returned by `GET /incidents/:id`. This mirrors the API's
 * own `IncidentDetail` (services/api/src/incidents.ts) built from schema
 * primitives — the web app deliberately does NOT depend on `@avekshak/api`, so
 * we restate the composite shape here rather than import it.
 */
export interface IncidentDetail extends Incident {
  alerts: Alert[];
  events: NormalizedEvent[];
  ledger: LedgerEntry[];
}

/**
 * The dry-run response plan carried on an approval. Mirrors the API's
 * `ResponsePlan` (services/api/src/response.ts). `target` is the attacker IP
 * when the correlation key is IP-based, else null.
 */
export interface ResponsePlan {
  dryRun: true;
  action: string;
  target: string | null;
  detail: string;
}

/**
 * Result of `POST /incidents/:id/approve|reject`. Mirrors the API's
 * `DecisionResult`. `response` is the dry-run plan on approval, null on reject.
 */
export interface DecisionResult {
  approval: Approval;
  incidentId: string;
  status: "approved" | "rejected";
  response: ResponsePlan | null;
}
