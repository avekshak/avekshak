import { randomUUID } from "node:crypto";
import { getDb, events, alerts, closeDb } from "@avekshak/db";
import { sql } from "drizzle-orm";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { NormalizedEvent } from "@avekshak/schema";
import { loadRulesFromDir } from "../src/rules/loader.js";
import { evaluate } from "../src/rules/evaluator.js";
import { syncRules, promoteAlert } from "../src/pipeline/alertWriter.js";

/**
 * Integration check for 2.3: inject events into the DB, run them through the
 * loaded rules, promote matches to alerts, and assert (a) alerts carry the
 * right rule_id/severity and (b) an identical event in the same window does
 * NOT create a second alert (dedupe holds).
 */

const DETECTIONS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../detections",
);

async function insertEvent(ev: NormalizedEvent): Promise<void> {
  await getDb()
    .insert(events)
    .values({
      id: ev.id,
      ts: new Date(ev.ts),
      source: ev.source,
      category: ev.category,
      action: ev.action,
      outcome: ev.outcome,
      severity: ev.severity,
      actorUser: ev.actor.user ?? null,
      actorIp: ev.actor.ip ?? null,
      targetHost: ev.target.host ?? null,
      raw: ev.raw,
    })
    .onConflictDoNothing({ target: events.id });
}

function failedLogin(id: string, ts: string): NormalizedEvent {
  return {
    id,
    ts,
    source: "syslog",
    category: "authentication",
    action: "login_failed",
    outcome: "failure",
    severity: 40,
    actor: { user: "root", ip: "203.0.113.9" },
    target: { host: "db-prod-1" },
    raw: {},
  };
}

async function main() {
  const db = getDb();
  const rules = await loadRulesFromDir(DETECTIONS_DIR);
  await syncRules(rules);

  // Clean slate: alerts first (FK), then our test events.
  await db.execute(sql`delete from ${alerts}`);
  await db.execute(sql`delete from ${events} where source = 'syslog' and actor_user = 'root'`);

  // Two identical-in-window failed logins (different event ids, same actor/ts-bucket).
  const e1 = failedLogin(randomUUID(), "2026-06-01T02:00:00.000Z");
  const e2 = failedLogin(randomUUID(), "2026-06-01T02:01:00.000Z"); // same 5-min bucket
  await insertEvent(e1);
  await insertEvent(e2);

  let created = 0;
  for (const ev of [e1, e2]) {
    const { matched } = evaluate(ev, rules);
    for (const rule of matched) {
      const isNew = await promoteAlert(ev, rule);
      if (isNew) created += 1;
    }
  }

  // Inspect the failed-login alert specifically.
  const rows = (await db.execute(
    sql`select rule_id, severity, actor_ip from ${alerts} where rule_id = 'auth-failed-login'`,
  )) as unknown as Array<{ rule_id: string; severity: number; actor_ip: string }>;

  const totalAlerts = (
    (await db.execute(sql`select count(*)::int as n from ${alerts}`)) as unknown as Array<{ n: number }>
  )[0].n;

  console.log("new alerts created across both events:", created);
  console.log("auth-failed-login rows:", rows);
  console.log("total alert rows:", totalAlerts);

  await closeDb();

  // e1 matches auth-failed-login + known-bad-ip (2 distinct rules → 2 alerts).
  // e2 is identical in-window → both its promotions are deduped (0 new).
  const failedLoginDeduped = rows.length === 1 && rows[0].severity === 40;
  const pass =
    failedLoginDeduped &&
    rows[0].actor_ip === "203.0.113.9" &&
    totalAlerts === 2; // auth-failed-login + known-bad-ip, each once
  console.log(
    pass
      ? "PASS: alerts carry correct rule_id/severity; in-window duplicate suppressed"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
