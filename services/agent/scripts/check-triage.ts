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
import { triageIncident } from "../src/triage/runner.js";

/**
 * Integration check for 4.3: a triage run turns an OPEN incident into TRIAGED
 * with a stored verdict and an ordered, append-only ledger trail — and takes no
 * response action. We use a deterministic FakeProvider so this gate runs with
 * no API key: it proves the worker/ledger/status WIRING. The real-LLM semantic
 * check (exfil = critical, owner login = benign, judged by Claude/Ollama) is the
 * Phase 4 integration gate. Even so, the fake mimics those two verdicts from the
 * incident content so the end-to-end shape matches the canonical scenarios.
 */

const RULE_ID = "triage-test-rule";

/** Deterministic stand-in for the LLM: judges from the incident's own facts. */
class FakeProvider implements LlmProvider {
  readonly name = "fake";
  async triage(ctx: IncidentContext): Promise<Verdict> {
    const looksExfil = ctx.alerts.some(
      (a) => a.ruleId.includes("exfil") || a.severity >= 80,
    );
    if (looksExfil) {
      return {
        verdict: "critical",
        confidence: 92,
        rationale: "Data exfiltration indicators on a sensitive target.",
        recommendedAction: "Isolate the host and rotate credentials.",
      };
    }
    return {
      verdict: "benign",
      confidence: 80,
      rationale: "Owner's own successful login; no anomaly beyond the hour.",
      recommendedAction: "No action; note for context.",
    };
  }
  async close(): Promise<void> {}
}

async function seedIncident(opts: {
  title: string;
  ruleId: string;
  severity: number;
  action: string;
  correlationKey: string;
  actorUser: string;
  actorIp: string;
}): Promise<string> {
  const db = getDb();
  const eventId = randomUUID();
  const alertId = randomUUID();
  const incidentId = randomUUID();
  const ts = new Date("2026-06-01T02:00:00.000Z");

  await db.insert(events).values({
    id: eventId,
    ts,
    source: "syslog",
    category: "authentication",
    action: opts.action,
    outcome: opts.severity >= 80 ? "unknown" : "success",
    severity: opts.severity,
    actorIp: opts.actorIp,
    actorUser: opts.actorUser,
    targetHost: "db-prod-1",
    raw: {},
  });
  await db.insert(alerts).values({
    id: alertId,
    eventId,
    ruleId: opts.ruleId,
    title: opts.title,
    severity: opts.severity,
    ts,
    actorIp: opts.actorIp,
    actorUser: opts.actorUser,
    targetHost: "db-prod-1",
    dedupeKey: alertId,
  });
  await db.insert(incidents).values({
    id: incidentId,
    title: opts.title,
    status: "open",
    severity: opts.severity,
    correlationKey: opts.correlationKey,
    createdAt: ts,
    updatedAt: ts,
  });
  await db.insert(incidentAlerts).values({ incidentId, alertId });
  return incidentId;
}

async function statusOf(incidentId: string): Promise<string> {
  const rows = await getDb()
    .select({ status: incidents.status })
    .from(incidents)
    .where(eq(incidents.id, incidentId))
    .limit(1);
  return rows[0].status;
}

async function verdictOf(incidentId: string): Promise<Verdict | null> {
  const rows = await getDb()
    .select({ verdict: incidents.verdict })
    .from(incidents)
    .where(eq(incidents.id, incidentId))
    .limit(1);
  return (rows[0].verdict as Verdict | null) ?? null;
}

async function main() {
  const db = getDb();

  // Clean slate. Delete the incident_alerts links by the incidents we own
  // (correlation_key), not by rule_id: a prior run of a DIFFERENT script may have
  // linked these same correlation keys through other rules, and a rule_id-scoped
  // delete would leave those links behind and trip the FK on the incident delete.
  await db.execute(
    sql`delete from ${incidentAlerts} where incident_id in (select id from ${incidents} where correlation_key in ('ip:203.0.113.52','ip:203.0.113.53'))`,
  );
  await db.execute(
    sql`delete from ${ledger} where incident_id in (select id from ${incidents} where correlation_key in ('ip:203.0.113.52','ip:203.0.113.53'))`,
  );
  await db.execute(
    sql`delete from ${incidents} where correlation_key in ('ip:203.0.113.52','ip:203.0.113.53')`,
  );
  await db.execute(sql`delete from ${alerts} where rule_id = ${RULE_ID}`);
  await db.execute(
    sql`delete from ${events} where actor_ip in ('203.0.113.52','203.0.113.53')`,
  );
  await db
    .insert(rulesTable)
    .values({ id: RULE_ID, title: "Triage test", severity: 40, definition: {}, enabled: 1 })
    .onConflictDoNothing();

  const provider = new FakeProvider();

  // Scenario 1: overseas DB exfiltration → should be critical.
  const exfilId = await seedIncident({
    title: "S3 exfiltration from foreign region",
    ruleId: RULE_ID,
    severity: 85,
    action: "Exfiltration:S3/ObjectRead.Unusual",
    correlationKey: "ip:203.0.113.52",
    actorUser: "svc-backup",
    actorIp: "203.0.113.52",
  });

  // Scenario 2: owner's own 4am root login → should be benign.
  const loginId = await seedIncident({
    title: "Root login success",
    ruleId: RULE_ID,
    severity: 40,
    action: "login_success",
    correlationKey: "ip:203.0.113.53",
    actorUser: "root",
    actorIp: "203.0.113.53",
  });

  const r1 = await triageIncident(exfilId, provider);
  const r2 = await triageIncident(loginId, provider);

  const exfilStatus = await statusOf(exfilId);
  const loginStatus = await statusOf(loginId);
  const exfilVerdict = await verdictOf(exfilId);
  const loginVerdict = await verdictOf(loginId);
  const exfilLedger = await readLedger(exfilId);

  console.log("exfil:", exfilStatus, "verdict:", exfilVerdict?.verdict, "conf:", exfilVerdict?.confidence);
  console.log("login:", loginStatus, "verdict:", loginVerdict?.verdict, "conf:", loginVerdict?.confidence);
  console.log("exfil ledger:", exfilLedger.map((e) => `${e.seq}:${e.action}`).join(" → "));

  await provider.close();
  await closeDb();

  const ledgerActions = exfilLedger.map((e) => e.action);
  const pass =
    // Status advanced open → triaged for both.
    exfilStatus === "triaged" &&
    loginStatus === "triaged" &&
    // Verdicts persisted and match the canonical scenarios.
    r1.verdict.verdict === "critical" &&
    exfilVerdict?.verdict === "critical" &&
    r2.verdict.verdict === "benign" &&
    loginVerdict?.verdict === "benign" &&
    // Ledger is an ordered, bracketed trail. With the 3-tier procedure the shape
    // is: context_gathered → score → verdict → status_changed. We assert the
    // presence + relative order of the key entries rather than fixed indices.
    ledgerActions[0] === "triage.context_gathered" &&
    ledgerActions.includes("triage.score") &&
    ledgerActions.includes("triage.verdict") &&
    ledgerActions.includes("incident.status_changed") &&
    ledgerActions.indexOf("triage.score") < ledgerActions.indexOf("triage.verdict") &&
    ledgerActions.indexOf("triage.verdict") <
      ledgerActions.indexOf("incident.status_changed") &&
    exfilLedger.every((e, i) => e.seq === i);

  console.log(
    pass
      ? "PASS: triage wiring — open→triaged, verdict stored, ordered ledger; no action taken"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
