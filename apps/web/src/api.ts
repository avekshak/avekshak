import type { Incident, IncidentDetail, DecisionResult } from "./types.js";

// All requests go through the Vite dev proxy: "/api/*" → http://localhost:8000
// (see vite.config.ts), so the browser stays same-origin and the API needs no
// CORS. In a production build there is no proxy — that would need same-origin
// hosting or CORS, which is out of MVP scope.
const BASE = "/api";

/**
 * A failed API call. Carries the HTTP status plus the API's structured error
 * body so the UI can tell apart a missing incident (404 `incident_not_found`)
 * from a decision made on the wrong state (409 `invalid_decision_state`, which
 * also reports the incident's current `status`).
 */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code?: string,
    readonly incidentStatus?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      headers: { "content-type": "application/json" },
      ...init,
    });
  } catch (err) {
    // Network-level failure (API down, proxy unreachable) — status 0.
    throw new ApiError(0, err instanceof Error ? err.message : "network error");
  }

  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as
      | { error?: string; status?: string }
      | null;
    throw new ApiError(
      res.status,
      body?.error ?? `request failed (${res.status})`,
      body?.error,
      body?.status,
    );
  }

  return (await res.json()) as T;
}

/** List incidents, already sorted severity DESC then updatedAt DESC by the API. */
export async function listIncidents(): Promise<Incident[]> {
  const body = await request<{ incidents: Incident[] }>("/incidents");
  return body.incidents;
}

/** Fetch one incident with its alerts, events, and full ledger. 404 → ApiError. */
export async function getIncident(id: string): Promise<IncidentDetail> {
  return request<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`);
}

/**
 * Approve the agent's recommendation — the human gate. Fires the dry-run
 * response. Sends no body; the API defaults `decidedBy` to "operator".
 * 404 (missing) / 409 (not triaged) → ApiError carrying `incidentStatus`.
 */
export async function approve(id: string): Promise<DecisionResult> {
  return request<DecisionResult>(`/incidents/${encodeURIComponent(id)}/approve`, {
    method: "POST",
    body: "{}",
  });
}

/** Reject the agent's recommendation. Records the decision, runs no response. */
export async function reject(id: string): Promise<DecisionResult> {
  return request<DecisionResult>(`/incidents/${encodeURIComponent(id)}/reject`, {
    method: "POST",
    body: "{}",
  });
}
