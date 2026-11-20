import { randomUUID } from "node:crypto";
import {
  getDb,
  events,
  rules as rulesTable,
  alerts,
  incidents,
  incidentAlerts,
  ledger,
  closeDb,
  readLedger,
} from "@avekshak/db";
import { sql, eq } from "drizzle-orm";
import type { Verdict } from "@avekshak/schema";
import type { IncidentContext, LlmProvider } from "../src/llm/provider.js";
import { LlmOutputError } from "../src/llm/provider.js";
import { triageIncident } from "../src/triage/runner.js";

/**
 * Integration check for 4.5.4: the groundedness gate and the deterministic
 * fallback, both driven by FakeProviders so this runs with NO network.
 *
 *  1. A provider that returns `benign` with a rationale citing an IP absent
 *     from the evidence → the tier-3 gate must demote it to `suspicious` and
 *     write `triage.gate_demotion`.
 *  2. A provider that THROWS (LLM unavailable) → the runner must fall back to
 *     the tier-1 deterministic verdict, persist it, and write `triage.fallback`
 *     — triage always produces an answer.
 *
 * Both incidents must also carry the `triage.score` tier-1 entry.
 */

const RULE_ID = "score-gate-test-rule";
const GATE_IP = "203.0.113.60";
const FALLBACK_IP = "203.0.113.61";
const GATE_KEY = `ip:${GATE_IP}`;
const FALLBACK_KEY = `ip:${FALLBACK_IP}`;

/** Returns benign but hallucinates an IP the evidence never contained. */
class HallucinatingBenignProvider implements LlmProvider {
  readonly name = "fake-hallucinate";
  async triage(_ctx: IncidentContext): Promise<Verdict> {
    return {
      verdict: "benign",
      confidence: 70,
      // 6.6.6.6 appears nowhere in the incident → groundedness 0 → demotion.
      rationale: "Benign: traffic was only to our internal host 6.6.6.6, nothing external.",
      recommendedAction: "No action.",
    };
  }
  async close(): Promise<void> {}
}

/** Always throws, as if the LLM endpoint were down / returned junk after retries. */
class ThrowingProvider implements LlmProvider {
  readonly name = "fake-throws";
  async triage(_ctx: IncidentContext): Promise<Verdict> {
    throw new LlmOutputError("fake-throws: no valid verdict after retries", "<<garbage>>");
  }
  async close(): Promise<void> {}
}

async function seedExfilIncident(correlationKey: string, actorIp: string): Promise<string> {
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
    status: "open",
    severity: 85,
    correlationKey,
    createdAt: ts,
    updatedAt: ts,
  });
  await db.insert(incidentAlerts).values({ incidentId, alertId });
  return incidentId;
}

async function verdictOf(incidentId: string): Promise<Verdict | null> {
  const rows = await getDb()
    .select({ verdict: incidents.verdict })
    .from(incidents)
    .where(eq(incidents.id, incidentId))
    .limit(1);
  return (rows[0]?.verdict as Verdict | null) ?? null;
}

async function cleanup(): Promise<void> {
  const db = getDb();
  await db.execute(
    sql`delete from ${incidentAlerts} where alert_id in (select id from ${alerts} where rule_id = ${RULE_ID})`,
  );
  await db.execute(
    sql`delete from ${ledger} where incident_id in (select id from ${incidents} where correlation_key in (${GATE_KEY}, ${FALLBACK_KEY}))`,
  );
  await db.execute(
    sql`delete from ${incidents} where correlation_key in (${GATE_KEY}, ${FALLBACK_KEY})`,
  );
  await db.execute(sql`delete from ${alerts} where rule_id = ${RULE_ID}`);
  await db.execute(sql`delete from ${events} where actor_ip in (${GATE_IP}, ${FALLBACK_IP})`);
}

async function main() {
  const db = getDb();
  await cleanup();
  await db
    .insert(rulesTable)
    .values({ id: RULE_ID, title: "Score gate test", severity: 85, definition: {}, enabled: 1 })
    .onConflictDoNothing();

  // Case 1 — benign + hallucinated IP → demotion.
  const gateId = await seedExfilIncident(GATE_KEY, GATE_IP);
  const gateResult = await triageIncident(gateId, new HallucinatingBenignProvider());
  const gateVerdict = await verdictOf(gateId);
  const gateLedger = await readLedger(gateId);
  const gateActions = gateLedger.map((e) => e.action);

  // Case 2 — LLM throws → deterministic fallback.
  const fbId = await seedExfilIncident(FALLBACK_KEY, FALLBACK_IP);
  const fbResult = await triageIncident(fbId, new ThrowingProvider());
  const fbVerdict = await verdictOf(fbId);
  const fbLedger = await readLedger(fbId);
  const fbActions = fbLedger.map((e) => e.action);

  console.log("gate case verdict:", gateResult.verdict.verdict);
  console.log("gate ledger:", gateActions.join(" → "));
  console.log("fallback case verdict:", fbResult.verdict.verdict, "conf:", fbResult.verdict.confidence);
  console.log("fallback ledger:", fbActions.join(" → "));

  await closeDb();

  const pass =
    // Case 1: benign demoted to suspicious; demotion + score recorded; persisted.
    gateResult.verdict.verdict === "suspicious" &&
    gateVerdict?.verdict === "suspicious" &&
    gateActions.includes("triage.score") &&
    gateActions.includes("triage.gate_demotion") &&
    gateActions.indexOf("triage.gate_demotion") < gateActions.indexOf("triage.verdict") &&
    gateLedger.every((e, i) => e.seq === i) &&
    // Case 2: deterministic fallback (exfil-shaped → critical from tier 1),
    // triage.failed + triage.fallback recorded; persisted; never threw.
    fbResult.verdict.verdict === "critical" &&
    fbVerdict?.verdict === "critical" &&
    fbActions.includes("triage.score") &&
    fbActions.includes("triage.failed") &&
    fbActions.includes("triage.fallback") &&
    fbActions.includes("triage.verdict") &&
    fbLedger.every((e, i) => e.seq === i);

  console.log(
    pass
      ? "PASS: tier-3 gate demotes hallucinated-benign; tier-1 fallback answers when the LLM fails"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
