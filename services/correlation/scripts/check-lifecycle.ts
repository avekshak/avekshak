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
import {
  transitionIncident,
  InvalidTransitionError,
} from "../src/correlate/lifecycle.js";

/**
 * Integration check for 3.3: incident status transitions obey the lifecycle
 * (open → triaged → approved → closed; illegal moves rejected), and linking the
 * same alert twice is a no-op (idempotent).
 */

const RULE_ID = "lifecycle-test-rule";
const IP = "203.0.113.210";

async function seedAlert(ts: string): Promise<Alert> {
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
    actorIp: IP,
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
    actorIp: IP,
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
    actorIp: IP,
    actorUser: "root",
    targetHost: "db-prod-1",
    dedupeKey: alert.id,
  });
  return alert;
}

async function count(incidentId: string): Promise<number> {
  const rows = (await getDb().execute(
    sql`select count(*)::int as n from ${incidentAlerts} where incident_id = ${incidentId}`,
  )) as unknown as Array<{ n: number }>;
  return rows[0].n;
}

async function status(incidentId: string): Promise<string> {
  const rows = await getDb()
    .select({ status: incidents.status })
    .from(incidents)
    .where(eq(incidents.id, incidentId))
    .limit(1);
  return rows[0].status;
}

async function main() {
  const db = getDb();
  // Clean slate.
  await db.execute(
    sql`delete from ${incidentAlerts} where alert_id in (select id from ${alerts} where rule_id = ${RULE_ID})`,
  );
  await db.execute(sql`delete from ${incidents} where correlation_key = ${"ip:" + IP}`);
  await db.execute(sql`delete from ${alerts} where rule_id = ${RULE_ID}`);
  await db.execute(sql`delete from ${events} where actor_ip = ${IP}`);
  await db
    .insert(rulesTable)
    .values({ id: RULE_ID, title: "Lifecycle test", severity: 40, definition: {}, enabled: 1 })
    .onConflictDoNothing();

  const correlator = new Correlator();
  const redis = (correlator as unknown as { redis: import("ioredis").Redis }).redis;
  await redis.del(`corr:ip:${IP}`);

  // --- Idempotent re-linking ---
  const alert = await seedAlert("2026-06-01T02:00:00.000Z");
  const r1 = await correlator.correlate(alert);
  const r2 = await correlator.correlate(alert); // same alert again
  const linkedAfterReLink = await count(r1.incidentId);

  console.log("first link linked:", r1.linked, "created:", r1.createdIncident);
  console.log("re-link linked:", r2.linked, "same incident:", r2.incidentId === r1.incidentId);
  console.log("links after double-correlate:", linkedAfterReLink);

  // --- Lifecycle transitions ---
  const incidentId = r1.incidentId;
  const s0 = await status(incidentId);
  await transitionIncident(incidentId, "triaged");
  const s1 = await status(incidentId);
  await transitionIncident(incidentId, "approved");
  const s2 = await status(incidentId);
  await transitionIncident(incidentId, "closed");
  const s3 = await status(incidentId);

  // Illegal: closed is terminal.
  let illegalRejected = false;
  try {
    await transitionIncident(incidentId, "open");
  } catch (err) {
    illegalRejected = err instanceof InvalidTransitionError;
  }

  // Illegal: can't skip triage (fresh incident).
  const alert2 = await seedAlert("2026-06-01T05:00:00.000Z"); // outside window → new incident
  await redis.del(`corr:ip:${IP}`);
  const r3 = await correlator.correlate(alert2);
  let skipRejected = false;
  try {
    await transitionIncident(r3.incidentId, "approved");
  } catch (err) {
    skipRejected = err instanceof InvalidTransitionError;
  }

  console.log(`transitions: ${s0} → ${s1} → ${s2} → ${s3}`);
  console.log("closed→open rejected:", illegalRejected);
  console.log("open→approved (skip triage) rejected:", skipRejected);

  await correlator.close();
  await closeDb();

  const pass =
    r1.linked === true &&
    r1.createdIncident === true &&
    r2.linked === false &&
    r2.incidentId === r1.incidentId &&
    linkedAfterReLink === 1 &&
    s0 === "open" &&
    s1 === "triaged" &&
    s2 === "approved" &&
    s3 === "closed" &&
    illegalRejected &&
    skipRejected;
  console.log(
    pass
      ? "PASS: lifecycle transitions enforced; re-linking idempotent"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
