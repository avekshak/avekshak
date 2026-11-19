import { randomUUID } from "node:crypto";
import {
  getDb,
  events,
  rules as rulesTable,
  alerts,
  incidents,
  incidentAlerts,
  closeDb,
} from "@avekshak/db";
import { sql, eq } from "drizzle-orm";
import type { Alert } from "@avekshak/schema";
import { Correlator } from "../src/correlate/correlator.js";

/**
 * Integration check for 3.2: 40 alerts sharing one attacker IP must collapse
 * into ONE incident with 40 linked alerts; alerts from unrelated IPs open their
 * own separate incidents.
 */

const RULE_ID = "corr-test-rule";
const ATTACKER_IP = "203.0.113.200";

async function seedEventAndAlert(
  actorIp: string,
  ts: string,
): Promise<Alert> {
  const eventId = randomUUID();
  const alertId = randomUUID();
  const db = getDb();
  await db.insert(events).values({
    id: eventId,
    ts: new Date(ts),
    source: "syslog",
    category: "authentication",
    action: "login_failed",
    outcome: "failure",
    severity: 40,
    actorIp,
    actorUser: "root",
    targetHost: "db-prod-1",
    raw: {},
  });
  const alert: Alert = {
    id: alertId,
    eventId,
    ruleId: RULE_ID,
    title: "Failed authentication",
    severity: 40,
    ts,
    actorIp,
    actorUser: "root",
    targetHost: "db-prod-1",
  };
  await db.insert(alerts).values({
    id: alert.id,
    eventId: alert.eventId,
    ruleId: alert.ruleId,
    title: alert.title,
    severity: alert.severity,
    ts: new Date(alert.ts),
    actorIp: alert.actorIp ?? null,
    actorUser: alert.actorUser ?? null,
    targetHost: alert.targetHost ?? null,
    dedupeKey: alert.id, // unique per alert here; dedupe tested elsewhere
  });
  return alert;
}

async function linkedCount(incidentId: string): Promise<number> {
  const rows = (await getDb().execute(
    sql`select count(*)::int as n from ${incidentAlerts} where incident_id = ${incidentId}`,
  )) as unknown as Array<{ n: number }>;
  return rows[0].n;
}

async function main() {
  const db = getDb();

  // Clean slate for this rule's data (order respects FKs).
  await db.execute(
    sql`delete from ${incidentAlerts} where alert_id in (select id from ${alerts} where rule_id = ${RULE_ID})`,
  );
  await db.execute(
    sql`delete from ${incidents} where correlation_key in ('ip:' || ${ATTACKER_IP}, 'ip:10.9.9.9', 'ip:10.9.9.10')`,
  );
  await db.execute(sql`delete from ${alerts} where rule_id = ${RULE_ID}`);
  await db.execute(sql`delete from ${events} where actor_ip in (${ATTACKER_IP}, '10.9.9.9', '10.9.9.10')`);

  await db
    .insert(rulesTable)
    .values({ id: RULE_ID, title: "Corr test", severity: 40, definition: {}, enabled: 1 })
    .onConflictDoNothing();

  const correlator = new Correlator();
  // Clear any stale Redis active-window keys.
  const redis = (correlator as unknown as { redis: import("ioredis").Redis }).redis;
  await redis.del(`corr:ip:${ATTACKER_IP}`, "corr:ip:10.9.9.9", "corr:ip:10.9.9.10");

  // 40 alerts from ONE attacker IP, spread across ~20 minutes (within window).
  const base = Date.parse("2026-06-01T02:00:00.000Z");
  const attackerIncidentIds = new Set<string>();
  for (let i = 0; i < 40; i += 1) {
    const ts = new Date(base + i * 30_000).toISOString(); // 30s apart
    const alert = await seedEventAndAlert(ATTACKER_IP, ts);
    const res = await correlator.correlate(alert);
    attackerIncidentIds.add(res.incidentId);
  }

  // 2 unrelated alerts from distinct IPs → 2 separate incidents.
  const u1 = await seedEventAndAlert("10.9.9.9", "2026-06-01T02:05:00.000Z");
  const u2 = await seedEventAndAlert("10.9.9.10", "2026-06-01T02:06:00.000Z");
  const r1 = await correlator.correlate(u1);
  const r2 = await correlator.correlate(u2);

  const attackerIncidentId = [...attackerIncidentIds][0];
  const attackerLinked = await linkedCount(attackerIncidentId);

  // Total incidents created for the three IPs.
  const incidentRows = (await db.execute(
    sql`select severity from ${incidents} where id = ${attackerIncidentId}`,
  )) as unknown as Array<{ severity: number }>;

  console.log("distinct attacker incident ids:", attackerIncidentIds.size);
  console.log("alerts linked to attacker incident:", attackerLinked);
  console.log("unrelated incidents distinct:", new Set([r1.incidentId, r2.incidentId]).size);
  console.log("attacker incident severity:", incidentRows[0]?.severity);

  await correlator.close();
  await closeDb();

  const pass =
    attackerIncidentIds.size === 1 &&
    attackerLinked === 40 &&
    r1.incidentId !== attackerIncidentId &&
    r2.incidentId !== attackerIncidentId &&
    r1.incidentId !== r2.incidentId;
  console.log(
    pass
      ? "PASS: 40 related alerts → 1 incident (40 linked); unrelated stay separate"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
