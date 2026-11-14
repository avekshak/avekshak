import { Redis } from "ioredis";
import { randomUUID } from "crypto";
import { getDb, alerts, rules as rulesTable } from "@avekshak/db";
import { createQueue } from "@avekshak/queue";
import type { NormalizedEvent } from "@avekshak/schema";
import type { Rule } from "./rule-schema.js";

const REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";
const redis = new Redis(REDIS_URL, { maxRetriesPerRequest: 1, lazyConnect: true });
const db = getDb();
const alertsQueue = createQueue("alerts");

function groupByValue(event: NormalizedEvent, groupBy: string): string | undefined {
  switch (groupBy) {
    case "actor.ip": return event.actor.ip;
    case "actor.user": return event.actor.user;
    case "target.host": return event.target.host;
    default: return undefined;
  }
}

export async function evaluateThreshold(event: NormalizedEvent, rule: Rule): Promise<boolean> {
  const t = rule.threshold;
  if (!t) return false;

  // Only count events that match the single-event condition
  const { field, operator, value } = rule.condition;
  const actual = field.includes(".")
    ? (event as unknown as Record<string, Record<string, unknown>>)[field.split(".")[0]]?.[field.split(".")[1]]
    : (event as unknown as Record<string, unknown>)[field];

  if (actual === undefined) return false;
  const matches =
    operator === "equals" ? String(actual).toLowerCase() === String(value).toLowerCase() :
    operator === "contains" ? String(actual).toLowerCase().includes(String(value).toLowerCase()) :
    false;
  if (!matches) return false;

  const groupValue = groupByValue(event, t.groupBy);
  if (!groupValue) return false;

  const key = `threshold:${rule.id}:${t.groupBy}:${groupValue}`;
  const count = await redis.incr(key);

  // Set TTL on first increment
  if (count === 1) {
    await redis.expire(key, t.windowSeconds);
  }

  if (count >= t.count) {
    // Reset counter so it can fire again after the window
    await redis.del(key);

    // Ensure rule exists
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
      title: `${rule.title} — ${t.groupBy}=${groupValue}`,
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
      title: `${rule.title} — ${t.groupBy}=${groupValue}`,
    });

    console.log(`[fusion] threshold alert: ${rule.title} groupBy=${t.groupBy} value=${groupValue} count=${count}`);
    return true;
  }

  return false;
}
