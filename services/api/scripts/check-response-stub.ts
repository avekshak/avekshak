import { randomUUID } from "node:crypto";
import {
  getDb,
  events,
  rules as rulesTable,
  alerts,
  incidents,
  incidentAlerts,
  ledger,
  approvals,
  appendLedger,
  readLedger,
  closeDb,
} from "@avekshak/db";
import { sql } from "drizzle-orm";
import { buildApp } from "../src/app.js";

/**
 * Integration check for 5.3 (response stub + human gate). The dry-run response
 * must run EXACTLY on approval and NEVER otherwise:
 *
 *   approve a triaged incident → `response.executed` appended once; the result
 *     carries a dry-run `block_ip` plan targeting the incident's attacker IP.
 *   reject a triaged incident  → NO `response.executed`; the gate held.
 *
 * The un-approved cases (un-triaged / double-decide) are covered by
 * check-approval-api.ts; here we focus on the response firing or not.
 * Real Postgres from `make up`; cleans up after itself.
 */

const RULE_ID = "response-stub-test-rule";
const APPROVE_IP = "203.0.113.90";
const REJECT_IP = "203.0.113.91";
const APPROVE_KEY = `ip:${APPROVE_IP}`;
const REJECT_KEY = `ip:${REJECT_IP}`;

async function seedTriaged(correlationKey: string, actorIp: string): Promise<string> {
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
    severity: 85,
    actorIp,
    actorUser: "svc-backup",
    targetHost: "db-prod-1",
    raw: {},
  });
  await db.insert(alerts).values({
    id: alertId,
    eventId,
    ruleId: RULE_ID,
    title: "Activity from a known-bad IP",
    severity: 85,
    ts,
    actorIp,
    actorUser: "svc-backup",
    targetHost: "db-prod-1",
    dedupeKey: alertId,
  });
  await db.insert(incidents).values({
    id: incidentId,
    title: "Activity from a known-bad IP",
    status: "triaged",
    severity: 85,
    correlationKey,
    verdict: {
      verdict: "critical",
      confidence: 92,
      rationale: "Data exfiltration from a sensitive target.",
      recommendedAction: "Isolate the host and rotate credentials.",
    },
    createdAt: ts,
    updatedAt: ts,
  });
  await db.insert(incidentAlerts).values({ incidentId, alertId });
  await appendLedger(incidentId, "agent", "triage.verdict", { verdict: "critical" });
  return incidentId;
}

async function cleanup(): Promise<void> {
  const db = getDb();
  await db.execute(
    sql`delete from ${approvals} where incident_id in (select id from ${incidents} where correlation_key in (${APPROVE_KEY}, ${REJECT_KEY}))`,
  );
  await db.execute(
    sql`delete from ${incidentAlerts} where alert_id in (select id from ${alerts} where rule_id = ${RULE_ID})`,
  );
  await db.execute(
    sql`delete from ${ledger} where incident_id in (select id from ${incidents} where correlation_key in (${APPROVE_KEY}, ${REJECT_KEY}))`,
  );
  await db.execute(
    sql`delete from ${incidents} where correlation_key in (${APPROVE_KEY}, ${REJECT_KEY})`,
  );
  await db.execute(sql`delete from ${alerts} where rule_id = ${RULE_ID}`);
  await db.execute(sql`delete from ${events} where actor_ip in (${APPROVE_IP}, ${REJECT_IP})`);
}

async function main() {
  const db = getDb();
  await cleanup();
  await db
    .insert(rulesTable)
    .values({ id: RULE_ID, title: "Response stub test", severity: 85, definition: {}, enabled: 1 })
    .onConflictDoNothing();

  const approveId = await seedTriaged(APPROVE_KEY, APPROVE_IP);
  const rejectId = await seedTriaged(REJECT_KEY, REJECT_IP);

  const app = buildApp();
  await app.ready();

  const approveRes = await app.inject({
    method: "POST",
    url: `/incidents/${approveId}/approve`,
    payload: { decidedBy: "alice" },
  });
  const approveBody = approveRes.json() as {
    status: string;
    response: { dryRun: boolean; action: string; target: string | null } | null;
  };
  const approveLedger = (await readLedger(approveId)).map((e) => e.action);

  const rejectRes = await app.inject({
    method: "POST",
    url: `/incidents/${rejectId}/reject`,
    payload: { decidedBy: "bob" },
  });
  const rejectBody = rejectRes.json() as { status: string; response: unknown };
  const rejectLedger = (await readLedger(rejectId)).map((e) => e.action);

  console.log("approve response:", JSON.stringify(approveBody.response));
  console.log("approve ledger:", approveLedger.join(" → "));
  console.log("reject response:", JSON.stringify(rejectBody.response));
  console.log("reject ledger:", rejectLedger.join(" → "));

  await app.close();
  await cleanup();
  await closeDb();

  const executedCount = approveLedger.filter((a) => a === "response.executed").length;
  const pass =
    // Approval fires the dry-run response exactly once, targeting the attacker IP.
    approveRes.statusCode === 200 &&
    approveBody.response !== null &&
    approveBody.response.dryRun === true &&
    approveBody.response.action === "block_ip" &&
    approveBody.response.target === APPROVE_IP &&
    executedCount === 1 &&
    approveLedger.includes("human.decision") &&
    approveLedger.indexOf("human.decision") < approveLedger.indexOf("response.executed") &&
    // Rejection holds the gate: decision recorded, response NOT run.
    rejectRes.statusCode === 200 &&
    rejectBody.response === null &&
    rejectLedger.includes("human.decision") &&
    !rejectLedger.includes("response.executed");

  console.log(
    pass
      ? "PASS: response stub runs once on approval (dry-run block_ip), never on rejection — human gate holds"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
