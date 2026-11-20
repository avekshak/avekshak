import { randomUUID } from "node:crypto";
import {
  getDb,
  events,
  rules as rulesTable,
  alerts,
  incidents,
  incidentAlerts,
  ledger,
  appendLedger,
  closeDb,
} from "@avekshak/db";
import { sql } from "drizzle-orm";
import { buildApp } from "../src/app.js";

/**
 * Integration check for 5.1 (read API). Seeds two incidents of differing
 * severity (each with a linked alert, its event, and a couple of ledger
 * entries), then exercises the HTTP surface via Fastify's in-process `inject`
 * (no live socket needed):
 *
 *   GET /incidents       → list, most severe first, header shape only.
 *   GET /incidents/:id   → detail: incident + alerts + events + full ledger.
 *   GET /incidents/<nil> → 404.
 *
 * Runs against the real Postgres from `make up`; cleans up after itself.
 */

const RULE_ID = "read-api-test-rule";
const HIGH_IP = "203.0.113.70";
const LOW_IP = "203.0.113.71";
const HIGH_KEY = `ip:${HIGH_IP}`;
const LOW_KEY = `ip:${LOW_IP}`;

async function seedIncident(opts: {
  title: string;
  severity: number;
  correlationKey: string;
  actorIp: string;
  status: string;
}): Promise<string> {
  const db = getDb();
  const eventId = randomUUID();
  const alertId = randomUUID();
  const incidentId = randomUUID();
  const ts = new Date("2026-06-01T02:00:00.000Z");

  await db.insert(events).values({
    id: eventId,
    ts,
    source: "aws",
    category: "cloud",
    action: "Exfiltration:S3/ObjectRead.Unusual",
    outcome: "unknown",
    severity: opts.severity,
    actorIp: opts.actorIp,
    actorUser: "svc-backup",
    targetHost: "db-prod-1",
    raw: {},
  });
  await db.insert(alerts).values({
    id: alertId,
    eventId,
    ruleId: RULE_ID,
    title: opts.title,
    severity: opts.severity,
    ts,
    actorIp: opts.actorIp,
    actorUser: "svc-backup",
    targetHost: "db-prod-1",
    dedupeKey: alertId,
  });
  await db.insert(incidents).values({
    id: incidentId,
    title: opts.title,
    status: opts.status,
    severity: opts.severity,
    correlationKey: opts.correlationKey,
    createdAt: ts,
    updatedAt: ts,
  });
  await db.insert(incidentAlerts).values({ incidentId, alertId });
  await appendLedger(incidentId, "agent", "triage.context_gathered", { alertCount: 1 });
  await appendLedger(incidentId, "agent", "triage.verdict", { verdict: "critical" });
  return incidentId;
}

async function cleanup(): Promise<void> {
  const db = getDb();
  await db.execute(
    sql`delete from ${incidentAlerts} where alert_id in (select id from ${alerts} where rule_id = ${RULE_ID})`,
  );
  await db.execute(
    sql`delete from ${ledger} where incident_id in (select id from ${incidents} where correlation_key in (${HIGH_KEY}, ${LOW_KEY}))`,
  );
  await db.execute(
    sql`delete from ${incidents} where correlation_key in (${HIGH_KEY}, ${LOW_KEY})`,
  );
  await db.execute(sql`delete from ${alerts} where rule_id = ${RULE_ID}`);
  await db.execute(sql`delete from ${events} where actor_ip in (${HIGH_IP}, ${LOW_IP})`);
}

async function main() {
  const db = getDb();
  await cleanup();
  await db
    .insert(rulesTable)
    .values({ id: RULE_ID, title: "Read API test", severity: 50, definition: {}, enabled: 1 })
    .onConflictDoNothing();

  const lowId = await seedIncident({
    title: "Low-severity incident",
    severity: 40,
    correlationKey: LOW_KEY,
    actorIp: LOW_IP,
    status: "open",
  });
  const highId = await seedIncident({
    title: "High-severity incident",
    severity: 90,
    correlationKey: HIGH_KEY,
    actorIp: HIGH_IP,
    status: "triaged",
  });

  const app = buildApp();
  await app.ready();

  // --- GET /incidents ---
  const listRes = await app.inject({ method: "GET", url: "/incidents" });
  const listBody = listRes.json() as { incidents: Array<{ id: string; severity: number }> };
  const ours = listBody.incidents.filter((i) => i.id === highId || i.id === lowId);
  const highIdx = listBody.incidents.findIndex((i) => i.id === highId);
  const lowIdx = listBody.incidents.findIndex((i) => i.id === lowId);

  // --- GET /incidents/:id (detail) ---
  const detailRes = await app.inject({ method: "GET", url: `/incidents/${highId}` });
  const detail = detailRes.json() as {
    id: string;
    severity: number;
    status: string;
    alerts: unknown[];
    events: unknown[];
    ledger: Array<{ seq: number; action: string }>;
  };

  // --- GET /incidents/<unknown> → 404 ---
  const missingRes = await app.inject({ method: "GET", url: `/incidents/${randomUUID()}` });

  console.log("list status:", listRes.statusCode, "returned", listBody.incidents.length, "incidents");
  console.log("high at index", highIdx, "low at index", lowIdx, "(severity-desc ⇒ high < low)");
  console.log("detail status:", detailRes.statusCode, "alerts:", detail.alerts.length, "events:", detail.events.length, "ledger:", detail.ledger.map((l) => `${l.seq}:${l.action}`).join(" → "));
  console.log("missing status:", missingRes.statusCode);

  await app.close();
  await cleanup();
  await closeDb();

  const pass =
    listRes.statusCode === 200 &&
    ours.length === 2 &&
    // Severity-desc: the high incident must appear before the low one.
    highIdx !== -1 &&
    lowIdx !== -1 &&
    highIdx < lowIdx &&
    // Detail shape: header + linked alert + its event + ordered ledger.
    detailRes.statusCode === 200 &&
    detail.id === highId &&
    detail.severity === 90 &&
    detail.status === "triaged" &&
    detail.alerts.length === 1 &&
    detail.events.length === 1 &&
    detail.ledger.length === 2 &&
    detail.ledger[0].seq === 0 &&
    detail.ledger[0].action === "triage.context_gathered" &&
    detail.ledger[1].action === "triage.verdict" &&
    // Unknown id → 404.
    missingRes.statusCode === 404;

  console.log(
    pass
      ? "PASS: read API — list severity-sorted, detail carries alerts/events/ledger, unknown id 404s"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
