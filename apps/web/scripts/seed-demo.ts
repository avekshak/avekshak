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
  closeDb,
} from "@avekshak/db";
import { sql } from "drizzle-orm";

/**
 * Interim demo seed for Phase 6 (the formal demo seed is Phase 7). The Phase-5
 * check-scripts clean up after themselves, so the DB is empty of incidents —
 * this gives the dashboard something to render. It is idempotent: it deletes
 * everything it previously created (by correlation key / rule id) and re-inserts,
 * so re-running leaves exactly these two incidents.
 *
 * Two canonical, already-triaged, verdict-bearing incidents:
 *   A — overseas data exfil: severity 90, critical verdict. IP-prefixed key so
 *       approving it yields a real-looking dry-run `block_ip`.
 *   B — owner's own 4 a.m. root login: severity 30, benign verdict. Sits as a
 *       low, non-escalated incident, exactly as the product intends.
 *
 * Adapts the insert pattern from services/api/scripts/check-approval-api.ts,
 * minus the test cleanup.
 */

const RULE_ID = "demo-seed-rule";

interface SeedSpec {
  correlationKey: string;
  actorIp: string;
  title: string;
  severity: number;
  action: string;
  category: string;
  actorUser: string;
  targetHost: string;
  verdict: {
    verdict: "benign" | "suspicious" | "critical";
    confidence: number;
    rationale: string;
    recommendedAction: string;
  };
}

const EXFIL: SeedSpec = {
  correlationKey: "ip:203.0.113.90",
  actorIp: "203.0.113.90",
  title: "Data exfiltration from a known-bad IP",
  severity: 90,
  action: "Exfiltration:S3/ObjectRead.Unusual",
  category: "cloud",
  actorUser: "svc-backup",
  targetHost: "db-prod-1",
  verdict: {
    verdict: "critical",
    confidence: 92,
    rationale:
      "A service account read an unusually large volume of objects from the production database host, egressing to an IP on the known-bad list. The volume, destination, and off-hours timing together indicate active data exfiltration.",
    recommendedAction:
      "Block the source IP, disable the svc-backup credentials, and isolate db-prod-1 pending review.",
  },
};

const OWNER_LOGIN: SeedSpec = {
  correlationKey: "ip:198.51.100.20",
  actorIp: "198.51.100.20",
  title: "Root login at 4 a.m. from an unusual location",
  severity: 30,
  action: "login_success",
  category: "authentication",
  actorUser: "root",
  targetHost: "bastion-1",
  verdict: {
    verdict: "benign",
    confidence: 70,
    rationale:
      "A single successful root login from an unusual geolocation at 4 a.m., with no failed attempts, no follow-on privileged actions, and no other correlated alerts. Consistent with the owner logging in while travelling.",
    recommendedAction:
      "No action required. Confirm with the account owner if out-of-band verification is desired.",
  },
};

const ALL_KEYS = [EXFIL.correlationKey, OWNER_LOGIN.correlationKey];
const ALL_IPS = [EXFIL.actorIp, OWNER_LOGIN.actorIp];

/** Remove anything a prior run of this seed created, respecting FK order. */
async function clearPrevious(): Promise<void> {
  const db = getDb();
  await db.execute(
    sql`delete from ${approvals} where incident_id in (select id from ${incidents} where correlation_key in (${EXFIL.correlationKey}, ${OWNER_LOGIN.correlationKey}))`,
  );
  await db.execute(
    sql`delete from ${incidentAlerts} where alert_id in (select id from ${alerts} where rule_id = ${RULE_ID})`,
  );
  await db.execute(
    sql`delete from ${ledger} where incident_id in (select id from ${incidents} where correlation_key in (${EXFIL.correlationKey}, ${OWNER_LOGIN.correlationKey}))`,
  );
  await db.execute(
    sql`delete from ${incidents} where correlation_key in (${EXFIL.correlationKey}, ${OWNER_LOGIN.correlationKey})`,
  );
  await db.execute(sql`delete from ${alerts} where rule_id = ${RULE_ID}`);
  await db.execute(sql`delete from ${events} where actor_ip in (${ALL_IPS[0]}, ${ALL_IPS[1]})`);
}

async function seedOne(spec: SeedSpec): Promise<string> {
  const db = getDb();
  const eventId = randomUUID();
  const alertId = randomUUID();
  const incidentId = randomUUID();
  const ts = new Date("2026-06-01T04:00:00.000Z");

  await db.insert(events).values({
    id: eventId,
    ts,
    source: "aws",
    category: spec.category,
    action: spec.action,
    outcome: spec.category === "authentication" ? "success" : "unknown",
    severity: spec.severity,
    actorIp: spec.actorIp,
    actorUser: spec.actorUser,
    targetHost: spec.targetHost,
    raw: {},
  });
  await db.insert(alerts).values({
    id: alertId,
    eventId,
    ruleId: RULE_ID,
    title: spec.title,
    severity: spec.severity,
    ts,
    actorIp: spec.actorIp,
    actorUser: spec.actorUser,
    targetHost: spec.targetHost,
    dedupeKey: alertId,
  });
  await db.insert(incidents).values({
    id: incidentId,
    title: spec.title,
    status: "triaged",
    severity: spec.severity,
    correlationKey: spec.correlationKey,
    verdict: spec.verdict,
    createdAt: ts,
    updatedAt: ts,
  });
  await db.insert(incidentAlerts).values({ incidentId, alertId });

  // A minimal but ordered ledger trail, so the detail view shows the AI's work.
  await appendLedger(incidentId, "agent", "triage.context_gathered", {
    alerts: 1,
    events: 1,
    correlationKey: spec.correlationKey,
  });
  await appendLedger(incidentId, "agent", "triage.score", {
    confidence: spec.verdict.confidence,
    verdict: spec.verdict.verdict,
    basis: [`alert severity ${spec.severity}`, `title: ${spec.title}`],
  });
  await appendLedger(incidentId, "agent", "triage.verdict", {
    verdict: spec.verdict.verdict,
    confidence: spec.verdict.confidence,
  });

  return incidentId;
}

async function main(): Promise<void> {
  const db = getDb();
  await clearPrevious();
  await db
    .insert(rulesTable)
    .values({ id: RULE_ID, title: "Demo seed", severity: 90, definition: {}, enabled: 1 })
    .onConflictDoNothing();

  const exfilId = await seedOne(EXFIL);
  const ownerId = await seedOne(OWNER_LOGIN);

  const rows = (await db.execute(
    sql`select count(*)::int as n from ${incidents} where correlation_key in (${ALL_KEYS[0]}, ${ALL_KEYS[1]})`,
  )) as unknown as Array<{ n: number }>;

  await closeDb();

  console.log(`seeded exfil incident:       ${exfilId} (critical, sev 90)`);
  console.log(`seeded owner-login incident: ${ownerId} (benign, sev 30)`);
  console.log(`incidents with demo keys now present: ${rows[0].n} (expected 2)`);
}

main().catch((err) => {
  console.error("seed failed:", err);
  process.exit(1);
});
