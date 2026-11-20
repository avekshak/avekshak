import { randomUUID } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  getDb,
  events,
  alerts,
  incidents,
  incidentAlerts,
  ledger,
  closeDb,
  readLedger,
} from "@avekshak/db";
import { sql, eq } from "drizzle-orm";
import type { NormalizedEvent, Verdict } from "@avekshak/schema";
import { ingestQueue, startIngestWorker } from "../../ingest/src/pipeline/ingestQueue.js";
import { loadRulesFromDir } from "../../fusion/src/rules/loader.js";
import { syncRules } from "../../fusion/src/pipeline/alertWriter.js";
import { WindowCounter } from "../../fusion/src/pipeline/windowCounter.js";
import { startFusionWorker } from "../../fusion/src/pipeline/detectQueue.js";
import { Correlator } from "../../correlation/src/correlate/correlator.js";
import { startCorrelationWorker } from "../../correlation/src/correlate/queue.js";
import { createProvider } from "../src/llm/index.js";
import { startTriageWorker } from "../src/triage/queue.js";

/**
 * PHASE 7 demo seed — "a scripted attack night".
 *
 * Unlike the interim web seed (which hand-writes DB rows), this replays raw
 * events through the WHOLE real pipeline — ingest → detect → correlate →
 * triage — exactly as production would, then prints the incidents that formed.
 * It is a demo, not a pass/fail gate (that's `smoke`), so it logs the grouping
 * story rather than asserting.
 *
 * The night contains two headline scenarios plus noise, to show the product's
 * central value: many raw signals collapse into a few investigated incidents.
 *   1. Overseas S3 data exfiltration from a known-bad IP  → should be critical.
 *   2. The owner's own 4 a.m. root login from holiday      → NOT critical.
 *   Noise: a brute-force burst (its own incident) and a lone file-integrity
 *   change — they stay SEPARATE from the headline incidents.
 *
 * Requires a live provider: LLM_PROVIDER=claude with ANTHROPIC_API_KEY (default)
 * or LLM_PROVIDER=ollama with the container running.
 */

const DETECTIONS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../detections",
);

const EXFIL_IP = "203.0.113.50"; // also a known-bad IP → a richer incident
const OWNER_IP = "198.51.100.200";
const BRUTE_IP = "192.0.2.77"; // noise: brute-force source
const FIM_IP = "192.0.2.88"; // noise: file-integrity change source

// Every identity this script touches, so we can clean the slate and later
// enumerate exactly the incidents the night produced.
const ALL_IPS = [EXFIL_IP, OWNER_IP, BRUTE_IP, FIM_IP];
const ALL_CORR_KEYS = ALL_IPS.map((ip) => `ip:${ip}`);

function exfilFinding(): NormalizedEvent {
  return {
    id: randomUUID(),
    ts: "2026-06-01T02:00:00.000Z",
    source: "aws",
    category: "cloud",
    action: "Exfiltration:S3/ObjectRead.Unusual",
    outcome: "unknown",
    severity: 85,
    actor: { user: "svc-backup", ip: EXFIL_IP },
    target: { resource: "s3://corp-financials-prod" },
    location: { country: "RU", city: "Moscow" },
    raw: { findingType: "Exfiltration:S3/ObjectRead.Unusual", region: "eu-west-1" },
  };
}

function ownerLogin(): NormalizedEvent {
  return {
    id: randomUUID(),
    ts: "2026-06-01T04:00:00.000Z",
    source: "syslog",
    category: "authentication",
    action: "login_success",
    outcome: "success",
    severity: 20,
    actor: { user: "root", ip: OWNER_IP },
    target: { host: "db-prod-1" },
    location: { country: "US", city: "Honolulu" },
    raw: { msg: "accepted publickey for root" },
  };
}

// Noise 1: five failed logins from one IP → fires the windowed brute-force rule.
function bruteForceBurst(): NormalizedEvent[] {
  return Array.from({ length: 5 }, (_, i) => ({
    id: randomUUID(),
    ts: `2026-06-01T03:0${i}:00.000Z`,
    source: "syslog" as const,
    category: "authentication",
    action: "login_failed",
    outcome: "failure" as const,
    severity: 30,
    actor: { user: "admin", ip: BRUTE_IP },
    target: { host: "web-edge-2" },
    raw: { msg: `failed password for admin (attempt ${i + 1})` },
  }));
}

// Noise 2: a lone file-integrity change → its own low-severity incident.
function fileIntegrityChange(): NormalizedEvent {
  return {
    id: randomUUID(),
    ts: "2026-06-01T03:30:00.000Z",
    source: "wazuh",
    category: "syscheck",
    action: "file_modified",
    outcome: "success",
    severity: 25,
    actor: { ip: FIM_IP },
    target: { host: "app-worker-5", resource: "/etc/cron.daily/logrotate" },
    raw: { syscheck: { path: "/etc/cron.daily/logrotate", event: "modified" } },
  };
}

async function clearSlate(): Promise<void> {
  const db = getDb();
  const keys = sql.join(
    ALL_CORR_KEYS.map((k) => sql`${k}`),
    sql`, `,
  );
  const ips = sql.join(
    ALL_IPS.map((ip) => sql`${ip}`),
    sql`, `,
  );
  await db.execute(
    sql`delete from ${ledger} where incident_id in (select id from ${incidents} where correlation_key in (${keys}))`,
  );
  await db.execute(
    sql`delete from ${incidentAlerts} where alert_id in (select id from ${alerts} where actor_ip in (${ips}))`,
  );
  await db.execute(sql`delete from ${incidents} where correlation_key in (${keys})`);
  await db.execute(sql`delete from ${alerts} where actor_ip in (${ips})`);
  await db.execute(sql`delete from ${events} where actor_ip in (${ips})`);
}

async function main() {
  const db = getDb();
  const rules = await loadRulesFromDir(DETECTIONS_DIR);
  await syncRules(rules);

  console.log("[seed] clearing prior demo-night state…");
  await clearSlate();

  // Live provider — fails fast with a clear message if no credential.
  const provider = createProvider();
  console.log(`[seed] provider: ${provider.name}`);

  const counter = new WindowCounter();
  const correlator = new Correlator();
  const orRedis = (correlator as unknown as { redis: import("ioredis").Redis }).redis;
  await orRedis.del(...ALL_CORR_KEYS.map((k) => `corr:${k}`));

  // Start the WHOLE pipeline.
  const ingestWorker = startIngestWorker();
  const fusionWorker = startFusionWorker(rules, counter);
  const correlationWorker = startCorrelationWorker(correlator);
  const triageWorker = startTriageWorker(provider);
  const queue = ingestQueue();

  console.log("[seed] replaying the night: exfil + owner-login + brute-force + file-change…");
  await queue.enqueue("aws", exfilFinding());
  await queue.enqueue("syslog", ownerLogin());
  for (const e of bruteForceBurst()) {
    await queue.enqueue("syslog", e);
  }
  await queue.enqueue("wazuh", fileIntegrityChange());

  // Poll until EVERY incident this night produced has settled (left 'open' for a
  // terminal triaged/approved/rejected state), so the report shows no half-done
  // rows. We require the two headline incidents to exist, then wait for all of
  // this night's incidents — headline + noise — to finish triage. Each step is a
  // real LLM round-trip, so allow a generous budget (~80s).
  for (let i = 0; i < 40; i += 1) {
    await sleep(2000);
    const headline = await db
      .select({ id: incidents.id })
      .from(incidents)
      .where(
        sql`${incidents.correlationKey} in (${sql.join(
          [sql`${`ip:${EXFIL_IP}`}`, sql`${`ip:${OWNER_IP}`}`],
          sql`, `,
        )})`,
      );
    if (headline.length < 2) continue;
    const settled = await db
      .select({ id: incidents.id })
      .from(incidents)
      .where(
        sql`${incidents.correlationKey} in (${sql.join(
          ALL_CORR_KEYS.map((k) => sql`${k}`),
          sql`, `,
        )}) and ${incidents.status} = 'open'`,
      );
    if (settled.length === 0) break;
  }

  // Report every incident the night produced, grouped by correlation key.
  const allRows = await db
    .select({
      id: incidents.id,
      title: incidents.title,
      status: incidents.status,
      severity: incidents.severity,
      correlationKey: incidents.correlationKey,
      verdict: incidents.verdict,
    })
    .from(incidents)
    .where(
      sql`${incidents.correlationKey} in (${sql.join(
        ALL_CORR_KEYS.map((k) => sql`${k}`),
        sql`, `,
      )})`,
    )
    .orderBy(sql`${incidents.severity} desc`);

  // Count the alerts folded into each incident — the grouping ratio story.
  let totalAlerts = 0;
  console.log("\n================  DEMO NIGHT: incidents formed  ================");
  for (const inc of allRows) {
    const [{ count }] = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(incidentAlerts)
      .where(eq(incidentAlerts.incidentId, inc.id));
    totalAlerts += count;
    const v = inc.verdict as Verdict | null;
    const led = await readLedger(inc.id);
    console.log(`\n• ${inc.title}  [${inc.correlationKey}]`);
    console.log(`    status=${inc.status}  severity=${inc.severity}  alerts=${count}`);
    if (v) {
      console.log(`    verdict=${v.verdict} (conf ${v.confidence})  — ${v.rationale}`);
      console.log(`    recommended: ${v.recommendedAction}`);
    } else {
      console.log("    verdict=(pending)");
    }
    console.log(`    ledger: ${led.map((e) => `${e.seq}:${e.action}`).join(" → ")}`);
  }
  console.log("\n----------------------------------------------------------------");
  console.log(
    `Grouped ${totalAlerts} alert(s) into ${allRows.length} incident(s). ` +
      "The exfil + owner-login are separate headline incidents; the brute-force " +
      "burst and file change stay as their own low-severity incidents.",
  );
  console.log("================================================================\n");

  await queue.close();
  await ingestWorker.close();
  await fusionWorker.close();
  await correlationWorker.close();
  await triageWorker.close();
  await counter.close();
  await correlator.close();
  await provider.close();
  await closeDb();
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
