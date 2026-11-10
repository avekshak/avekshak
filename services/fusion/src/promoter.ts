import { randomUUID } from "crypto";
import { createDb, alerts, rules as rulesTable } from "@avekshak/db";
import { createQueue } from "@avekshak/queue";
import { eq, and, gte } from "drizzle-orm";
import type { NormalizedEvent } from "@avekshak/schema";
import type { Rule } from "./rule-schema.js";

const db = createDb();
const alertsQueue = createQueue("alerts");

// Dedupe window: suppress identical (eventId, ruleId) within 5 minutes
const DEDUPE_WINDOW_MS = 5 * 60 * 1000;

export async function promoteAlert(event: NormalizedEvent, rule: Rule): Promise<boolean> {
  const windowStart = new Date(Date.now() - DEDUPE_WINDOW_MS);

  // Check for duplicate alert in the dedupe window
  const existing = await db
    .select({ id: alerts.id })
    .from(alerts)
    .where(
      and(
        eq(alerts.eventId, event.id),
        eq(alerts.ruleId, rule.id),
        gte(alerts.createdAt, windowStart),
      ),
    )
    .limit(1);

  if (existing.length > 0) {
    return false; // suppressed duplicate
  }

  // Ensure rule exists in rules table (upsert)
  await db
    .insert(rulesTable)
    .values({
      id: rule.id,
      title: rule.title,
      description: rule.description ?? null,
      category: rule.category,
      severity: rule.severity,
      yaml: rule.id,
    })
    .onConflictDoNothing();

  const alertId = randomUUID();
  await db.insert(alerts).values({
    id: alertId,
    eventId: event.id,
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    ts: new Date(event.ts),
    actorIp: event.actor.ip ?? null,
    actorUser: event.actor.user ?? null,
    targetHost: event.target.host ?? null,
  });

  await alertsQueue.enqueue("alert", {
    id: alertId,
    ts: event.ts,
    severity: rule.severity,
    actorIp: event.actor.ip ?? null,
    actorUser: event.actor.user ?? null,
    targetHost: event.target.host ?? null,
    title: rule.title,
  });

  console.log(`[fusion] alert: ${rule.title} (severity=${rule.severity}) event=${event.id}`);
  return true;
}
