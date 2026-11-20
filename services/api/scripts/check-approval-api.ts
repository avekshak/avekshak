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
import { sql, eq } from "drizzle-orm";
import { buildApp } from "../src/app.js";

/**
 * Integration check for 5.2 (approval API). The human gate:
 *
 *   POST /incidents/:id/approve  (triaged) → 200; status→approved, approvals
 *                                 row written, `human.decision` in the ledger.
 *   POST /incidents/:id/approve  (again)   → 409; no second approval row.
 *   POST /incidents/:id/reject   (triaged) → 200; status→rejected.
 *   POST /incidents/:id/approve  (open)    → 409; un-triaged can't be decided.
 *   POST /incidents/<unknown>/approve      → 404.
 *
 * Real Postgres from `make up`; cleans up after itself.
 */

const RULE_ID = "approval-api-test-rule";
const APPROVE_IP = "203.0.113.80";
const REJECT_IP = "203.0.113.81";
const OPEN_IP = "203.0.113.82";
const APPROVE_KEY = `ip:${APPROVE_IP}`;
const REJECT_KEY = `ip:${REJECT_IP}`;
const OPEN_KEY = `ip:${OPEN_IP}`;

async function seedIncident(opts: {
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
    severity: 85,
    actorIp: opts.actorIp,
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
    actorIp: opts.actorIp,
    actorUser: "svc-backup",
    targetHost: "db-prod-1",
    dedupeKey: alertId,
  });
  await db.insert(incidents).values({
    id: incidentId,
    title: "Activity from a known-bad IP",
    status: opts.status,
    severity: 85,
    correlationKey: opts.correlationKey,
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

async function statusOf(incidentId: string): Promise<string> {
  const rows = await getDb()
    .select({ status: incidents.status })
    .from(incidents)
    .where(eq(incidents.id, incidentId))
    .limit(1);
  return rows[0]?.status ?? "<none>";
}

async function approvalCount(incidentId: string): Promise<number> {
  const rows = (await getDb().execute(
    sql`select count(*)::int as n from ${approvals} where incident_id = ${incidentId}`,
  )) as unknown as Array<{ n: number }>;
  return rows[0].n;
}

async function cleanup(): Promise<void> {
  const db = getDb();
  await db.execute(
    sql`delete from ${approvals} where incident_id in (select id from ${incidents} where correlation_key in (${APPROVE_KEY}, ${REJECT_KEY}, ${OPEN_KEY}))`,
  );
  await db.execute(
    sql`delete from ${incidentAlerts} where alert_id in (select id from ${alerts} where rule_id = ${RULE_ID})`,
  );
  await db.execute(
    sql`delete from ${ledger} where incident_id in (select id from ${incidents} where correlation_key in (${APPROVE_KEY}, ${REJECT_KEY}, ${OPEN_KEY}))`,
  );
  await db.execute(
    sql`delete from ${incidents} where correlation_key in (${APPROVE_KEY}, ${REJECT_KEY}, ${OPEN_KEY})`,
  );
  await db.execute(sql`delete from ${alerts} where rule_id = ${RULE_ID}`);
  await db.execute(
    sql`delete from ${events} where actor_ip in (${APPROVE_IP}, ${REJECT_IP}, ${OPEN_IP})`,
  );
}

async function main() {
  const db = getDb();
  await cleanup();
  await db
    .insert(rulesTable)
    .values({ id: RULE_ID, title: "Approval API test", severity: 85, definition: {}, enabled: 1 })
    .onConflictDoNothing();

  const approveId = await seedIncident({ correlationKey: APPROVE_KEY, actorIp: APPROVE_IP, status: "triaged" });
  const rejectId = await seedIncident({ correlationKey: REJECT_KEY, actorIp: REJECT_IP, status: "triaged" });
  const openId = await seedIncident({ correlationKey: OPEN_KEY, actorIp: OPEN_IP, status: "open" });

  const app = buildApp();
  await app.ready();

  // 1. Approve a triaged incident.
  const approveRes = await app.inject({
    method: "POST",
    url: `/incidents/${approveId}/approve`,
    payload: { decidedBy: "alice", note: "confirmed exfil" },
  });
  const approveStatus = await statusOf(approveId);
  const approveLedger = (await readLedger(approveId)).map((e) => e.action);
  const approveCount1 = await approvalCount(approveId);

  // 2. Approve again → rejected (409), no new approval row.
  const doubleRes = await app.inject({
    method: "POST",
    url: `/incidents/${approveId}/approve`,
    payload: { decidedBy: "alice" },
  });
  const approveCount2 = await approvalCount(approveId);

  // 3. Reject a different triaged incident.
  const rejectRes = await app.inject({
    method: "POST",
    url: `/incidents/${rejectId}/reject`,
    payload: { decidedBy: "bob", note: "false positive" },
  });
  const rejectStatus = await statusOf(rejectId);

  // 4. Decide an un-triaged (open) incident → 409.
  const openRes = await app.inject({
    method: "POST",
    url: `/incidents/${openId}/approve`,
    payload: { decidedBy: "carol" },
  });
  const openStatus = await statusOf(openId);

  // 5. Decide an unknown incident → 404.
  const missingRes = await app.inject({
    method: "POST",
    url: `/incidents/${randomUUID()}/approve`,
    payload: { decidedBy: "dave" },
  });

  console.log("approve:", approveRes.statusCode, "→", approveStatus, "ledger:", approveLedger.join(" → "), "approvals:", approveCount1);
  console.log("double-approve:", doubleRes.statusCode, "approvals now:", approveCount2);
  console.log("reject:", rejectRes.statusCode, "→", rejectStatus);
  console.log("decide-open:", openRes.statusCode, "status unchanged:", openStatus);
  console.log("decide-missing:", missingRes.statusCode);

  await app.close();
  await cleanup();
  await closeDb();

  const pass =
    // 1. Approve succeeds; status flips; approval + human.decision recorded.
    approveRes.statusCode === 200 &&
    approveStatus === "approved" &&
    approveCount1 === 1 &&
    approveLedger.includes("human.decision") &&
    // 2. Double-approve is a conflict and writes no second row.
    doubleRes.statusCode === 409 &&
    approveCount2 === 1 &&
    // 3. Reject works symmetrically.
    rejectRes.statusCode === 200 &&
    rejectStatus === "rejected" &&
    // 4. An open (un-triaged) incident cannot be decided.
    openRes.statusCode === 409 &&
    openStatus === "open" &&
    // 5. Unknown incident → 404.
    missingRes.statusCode === 404;

  console.log(
    pass
      ? "PASS: approval API — triaged→approved/rejected with ledger+row; double-decide & un-triaged 409; unknown 404"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
