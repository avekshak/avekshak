import type { Alert } from "@avekshak/schema";

/** How long an incident stays "open" for new alerts to join it. */
export const CORRELATION_WINDOW_MS = 30 * 60 * 1000; // 30 minutes

/**
 * The single identity an alert correlates on, chosen in priority order:
 * actor.ip → actor.user → target.host. One primary key per alert keeps the
 * MVP's grouping deterministic (no multi-identity graph union): every alert
 * sharing that key within the window lands in the same incident.
 *
 * Returns null when an alert has no correlatable identity — such alerts each
 * get their own singleton incident rather than being forced together.
 */
export function correlationKey(alert: Alert): string | null {
  if (alert.actorIp) return `ip:${alert.actorIp}`;
  if (alert.actorUser) return `user:${alert.actorUser}`;
  if (alert.targetHost) return `host:${alert.targetHost}`;
  return null;
}

/**
 * Two alerts correlate when they share a (non-null) correlation key AND their
 * timestamps fall within CORRELATION_WINDOW_MS of each other. Pure and
 * symmetric — used for unit-testing the grouping logic in isolation.
 */
export function alertsCorrelate(
  a: Alert,
  b: Alert,
  windowMs: number = CORRELATION_WINDOW_MS,
): boolean {
  const ka = correlationKey(a);
  const kb = correlationKey(b);
  if (ka === null || kb === null) return false;
  if (ka !== kb) return false;
  const dt = Math.abs(Date.parse(a.ts) - Date.parse(b.ts));
  return dt <= windowMs;
}

/**
 * Whether an incoming alert still falls inside an open incident's window,
 * measured from the incident's most recent activity (its latest linked alert
 * timestamp). Keeps a long-running attack's incident "alive" as long as alerts
 * keep arriving within the window of the last one.
 */
export function withinWindow(
  alertTs: string,
  incidentLatestTs: string,
  windowMs: number = CORRELATION_WINDOW_MS,
): boolean {
  const dt = Date.parse(alertTs) - Date.parse(incidentLatestTs);
  return Math.abs(dt) <= windowMs;
}
