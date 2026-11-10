// Correlation window: alerts within this period sharing a key are the same incident
export const CORRELATION_WINDOW_MS = 30 * 60 * 1000; // 30 minutes

export interface AlertSummary {
  id: string;
  ts: Date;
  severity: number;
  actorIp: string | null;
  actorUser: string | null;
  targetHost: string | null;
  title: string;
}

// Returns the correlation key for an alert, or null if no groupable field exists.
// Priority: actor.ip > actor.user > target.host
export function correlationKey(alert: AlertSummary): string | null {
  if (alert.actorIp) return `ip:${alert.actorIp}`;
  if (alert.actorUser) return `user:${alert.actorUser}`;
  if (alert.targetHost) return `host:${alert.targetHost}`;
  return null;
}

// Returns true if two alerts share a correlation key and fall within the window.
export function shouldCorrelate(a: AlertSummary, b: AlertSummary): boolean {
  const ka = correlationKey(a);
  const kb = correlationKey(b);
  if (!ka || !kb || ka !== kb) return false;
  return Math.abs(a.ts.getTime() - b.ts.getTime()) <= CORRELATION_WINDOW_MS;
}
