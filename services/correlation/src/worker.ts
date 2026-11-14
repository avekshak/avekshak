import { randomUUID } from "crypto";
import { Redis } from "ioredis";
import { createWorker } from "@avekshak/queue";
import { getDb, incidents, incidentAlerts, alerts } from "@avekshak/db";
import { eq, and, gt } from "drizzle-orm";
import { correlationKey, CORRELATION_WINDOW_MS } from "./correlate.js";
import type { AlertSummary } from "./correlate.js";

const REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";
const redis = new Redis(REDIS_URL, { maxRetriesPerRequest: 1, lazyConnect: true });
const db = getDb();

// Redis key for the active incident id for a given correlation key
function incidentKey(corrKey: string): string {
  return `incident:active:${corrKey}`;
}

// How long to keep the Redis active-incident pointer (TTL = window + 5 min buffer)
const REDIS_TTL_SECONDS = Math.ceil(CORRELATION_WINDOW_MS / 1000) + 300;

interface AlertJob {
  id: string;
  ts: string;
  severity: number;
  actorIp: string | null;
  actorUser: string | null;
  targetHost: string | null;
  title: string;
}

export function startCorrelationWorker(): void {
  createWorker<AlertJob>("alerts", async (job) => {
    const alert: AlertSummary = {
      id: job.data.id,
      ts: new Date(job.data.ts),
      severity: job.data.severity,
      actorIp: job.data.actorIp,
      actorUser: job.data.actorUser,
      targetHost: job.data.targetHost,
      title: job.data.title,
    };

    const corrKey = correlationKey(alert);

    if (!corrKey) {
      // No groupable field — open a standalone incident
      await createIncident(alert, `standalone:${alert.id}`);
      return;
    }

    // Check Redis for an active incident in the window
    const existingId = await redis.get(incidentKey(corrKey));

    if (existingId) {
      // Link alert to existing incident (idempotent)
      await linkAlert(existingId, alert.id);
      // Extend the TTL so the window slides with new activity
      await redis.expire(incidentKey(corrKey), REDIS_TTL_SECONDS);
    } else {
      // Check DB for a recently-created open incident with same correlation key
      // (covers restarts where Redis was flushed)
      const windowStart = new Date(Date.now() - CORRELATION_WINDOW_MS);
      const existing = await db
        .select({ id: incidents.id })
        .from(incidents)
        .where(
          and(
            eq(incidents.correlationKey, corrKey),
            eq(incidents.status, "open"),
            gt(incidents.createdAt, windowStart),
          ),
        )
        .limit(1);

      if (existing.length > 0) {
        const incidentId = existing[0].id;
        await redis.set(incidentKey(corrKey), incidentId, "EX", REDIS_TTL_SECONDS);
        await linkAlert(incidentId, alert.id);
      } else {
        await createIncident(alert, corrKey);
      }
    }
  });

  console.log("[correlation] worker started");
}

async function createIncident(alert: AlertSummary, corrKey: string): Promise<string> {
  const id = randomUUID();
  await db.insert(incidents).values({
    id,
    title: alert.title,
    status: "open",
    severity: alert.severity,
    correlationKey: corrKey,
  });

  await linkAlert(id, alert.id);

  // Register in Redis so the next alert in the window finds it
  await redis.set(incidentKey(corrKey), id, "EX", REDIS_TTL_SECONDS);

  console.log(`[correlation] new incident ${id} corrKey=${corrKey}`);
  return id;
}

async function linkAlert(incidentId: string, alertId: string): Promise<void> {
  // Update incident severity to max of current + new alert
  const [alertRow] = await db
    .select({ severity: alerts.severity })
    .from(alerts)
    .where(eq(alerts.id, alertId))
    .limit(1);

  if (alertRow) {
    const [incident] = await db
      .select({ severity: incidents.severity })
      .from(incidents)
      .where(eq(incidents.id, incidentId))
      .limit(1);

    if (incident && alertRow.severity > incident.severity) {
      await db
        .update(incidents)
        .set({ severity: alertRow.severity, updatedAt: new Date() })
        .where(eq(incidents.id, incidentId));
    }
  }

  // idempotent insert — ignore duplicate (incidentId, alertId) pairs
  await db
    .insert(incidentAlerts)
    .values({ incidentId, alertId })
    .onConflictDoNothing();

  console.log(`[correlation] linked alert=${alertId} → incident=${incidentId}`);
}
