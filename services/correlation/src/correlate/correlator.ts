import { v4 as uuidv4 } from "uuid";
import { Redis } from "ioredis";
import { getDb, incidents, incidentAlerts } from "@avekshak/db";
import { and, eq, gte, sql } from "drizzle-orm";
import type { Alert } from "@avekshak/schema";
import { correlationKey, CORRELATION_WINDOW_MS } from "./keys.js";

const REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";

export interface CorrelateResult {
  incidentId: string;
  /** True if this alert opened a brand-new incident. */
  createdIncident: boolean;
  /** True if the alert was newly linked (false if it was already linked). */
  linked: boolean;
}

/**
 * Correlates one alert into an incident.
 *
 * Grouping strategy: an alert's correlation key (ip → user → host) maps to at
 * most one *active* incident at a time. Redis holds `corr:{key} → incidentId`
 * with a TTL equal to the correlation window, so a burst of related alerts all
 * find the same incident; once the window lapses, the next alert opens a fresh
 * one. Postgres is the durable store; Redis is only the fast "what's open now"
 * index and is rebuildable from it.
 */
export class Correlator {
  private redis: Redis;

  constructor(redis?: Redis) {
    this.redis = redis ?? new Redis(REDIS_URL, { maxRetriesPerRequest: null });
  }

  private activeKey(correlation: string): string {
    return `corr:${correlation}`;
  }

  /**
   * Find the active incident id for a correlation key: first the Redis index,
   * then a Postgres fallback (an open incident with the same key whose last
   * activity is still within the window) so a cold Redis doesn't fragment an
   * ongoing incident. Returns null when a new incident should be opened.
   */
  private async findActiveIncident(
    correlation: string,
    alertTs: string,
  ): Promise<string | null> {
    const cached = await this.redis.get(this.activeKey(correlation));
    if (cached) return cached;

    const cutoff = new Date(Date.parse(alertTs) - CORRELATION_WINDOW_MS);
    const rows = await getDb()
      .select({ id: incidents.id })
      .from(incidents)
      .where(
        and(
          eq(incidents.correlationKey, correlation),
          eq(incidents.status, "open"),
          gte(incidents.updatedAt, cutoff),
        ),
      )
      .orderBy(sql`${incidents.updatedAt} desc`)
      .limit(1);
    return rows[0]?.id ?? null;
  }

  async correlate(alert: Alert): Promise<CorrelateResult> {
    // Alerts with no correlatable identity get a unique singleton key so they
    // each open their own incident (never grouped with unrelated noise).
    const correlation = correlationKey(alert) ?? `singleton:${alert.id}`;
    const db = getDb();

    let incidentId = await this.findActiveIncident(correlation, alert.ts);
    let createdIncident = false;

    if (!incidentId) {
      incidentId = uuidv4();
      await db.insert(incidents).values({
        id: incidentId,
        title: alert.title,
        status: "open",
        severity: alert.severity,
        correlationKey: correlation,
        createdAt: new Date(alert.ts),
        updatedAt: new Date(alert.ts),
      });
      createdIncident = true;
    }

    // Link idempotently (composite PK (incidentId, alertId)).
    const linkedRows = await db
      .insert(incidentAlerts)
      .values({ incidentId, alertId: alert.id })
      .onConflictDoNothing()
      .returning({ alertId: incidentAlerts.alertId });
    const linked = linkedRows.length > 0;

    if (linked && !createdIncident) {
      // Escalate incident severity to the max of its alerts, and advance its
      // activity timestamp so the window tracks the latest alert.
      await db
        .update(incidents)
        .set({
          severity: sql`greatest(${incidents.severity}, ${alert.severity})`,
          updatedAt: new Date(alert.ts),
        })
        .where(eq(incidents.id, incidentId));
    }

    // Refresh the active-window index.
    await this.redis.set(
      this.activeKey(correlation),
      incidentId,
      "PX",
      CORRELATION_WINDOW_MS,
    );

    return { incidentId, createdIncident, linked };
  }

  async close(): Promise<void> {
    await this.redis.quit();
  }
}
