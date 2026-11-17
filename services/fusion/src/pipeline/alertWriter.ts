import { getDb, rules as rulesTable, alerts } from "@avekshak/db";
import type { Alert, Rule } from "@avekshak/schema";
import { buildAlert } from "./promote.js";
import type { NormalizedEvent } from "@avekshak/schema";

/**
 * Upsert the loaded rule set into the `rules` table so that alert rows can
 * reference them via FK. Rules are the source of truth in YAML; the table is a
 * projection kept in sync on startup. `definition` stores the full rule for
 * audit/debug.
 */
export async function syncRules(rules: Rule[]): Promise<void> {
  if (rules.length === 0) return;
  const db = getDb();
  for (const r of rules) {
    await db
      .insert(rulesTable)
      .values({
        id: r.id,
        title: r.title,
        severity: r.severity,
        definition: r as unknown as Record<string, unknown>,
        enabled: r.enabled ? 1 : 0,
      })
      .onConflictDoUpdate({
        target: rulesTable.id,
        set: {
          title: r.title,
          severity: r.severity,
          definition: r as unknown as Record<string, unknown>,
          enabled: r.enabled ? 1 : 0,
        },
      });
  }
}

/**
 * Insert an alert, deduping on the unique dedupe_key. Returns true if a new
 * row was created, false if an identical alert already existed in the window.
 */
export async function writeAlert(
  alert: Alert,
  dedupeKey: string,
): Promise<boolean> {
  const inserted = await getDb()
    .insert(alerts)
    .values({
      id: alert.id,
      eventId: alert.eventId,
      ruleId: alert.ruleId,
      title: alert.title,
      severity: alert.severity,
      ts: new Date(alert.ts),
      actorIp: alert.actorIp ?? null,
      actorUser: alert.actorUser ?? null,
      targetHost: alert.targetHost ?? null,
      dedupeKey,
    })
    .onConflictDoNothing({ target: alerts.dedupeKey })
    .returning({ id: alerts.id });
  return inserted.length > 0;
}

/**
 * Promote a single matched (event, rule) pair into an alert row, deduped.
 * Returns the created Alert when a new row was written, or null if an identical
 * alert already existed in the window (so callers can forward only genuinely
 * new alerts downstream).
 */
export async function promoteAlert(
  ev: NormalizedEvent,
  rule: Rule,
): Promise<Alert | null> {
  const { alert, dedupeKey } = buildAlert(ev, rule);
  const isNew = await writeAlert(alert, dedupeKey);
  return isNew ? alert : null;
}
