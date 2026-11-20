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
 * PHASE 7 smoke test — the automated end-to-end gate.
 *
 * Drives the WHOLE real pipeline (ingest → detect → correlate → triage) with a
 * live LLM, exactly like the demo seed, but instead of printing a story it
 * ASSERTS the product's load-bearing properties and exits non-zero on failure:
 *   1. The overseas exfil (known-bad IP) becomes a dangerous incident
 *      (critical, or at least suspicious) that folded multiple alerts into one.
 *   2. The owner's own 4 a.m. root login is NOT escalated to critical.
 *   3. The noise (brute-force burst, file-integrity change) stays as its OWN
 *      separate incidents — grouping does not smear unrelated alerts together.
 *   4. Each headline incident carries an ordered, readable ledger trail.
 *
 * Why not strict "benign" for the owner login: the MVP has no identity/history/
 * UEBA enrichment (scoped out), so the only fact that would prove a lone root
 * login benign — "this is the owner" — exists in no field the agent can see.
 * An honest agent lands on "suspicious → human confirms". What the gate protects
 * is that it does NOT cry critical and wake everyone.
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

const EXFIL_KEY = `ip:${EXFIL_IP}`;
const OWNER_KEY = `ip:${OWNER_IP}`;
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
  await clearSlate();

  const provider = createProvider();
  console.log(`[smoke] provider: ${provider.name}`);

  const counter = new WindowCounter();
  const correlator = new Correlator();
  const orRedis = (correlator as unknown as { redis: import("ioredis").Redis }).redis;
  await orRedis.del(...ALL_CORR_KEYS.map((k) => `corr:${k}`));

  const ingestWorker = startIngestWorker();
  const fusionWorker = startFusionWorker(rules, counter);
  const correlationWorker = startCorrelationWorker(correlator);
  const triageWorker = startTriageWorker(provider);
  const queue = ingestQueue();

  await queue.enqueue("aws", exfilFinding());
  await queue.enqueue("syslog", ownerLogin());
  for (const e of bruteForceBurst()) {
    await queue.enqueue("syslog", e);
  }
  await queue.enqueue("wazuh", fileIntegrityChange());

  // Wait for the two headline incidents to triage (a real LLM round-trip each).
  let exfil: { id: string; status: string; verdict: Verdict | null } | null = null;
  let owner: { id: string; status: string; verdict: Verdict | null } | null = null;
  for (let i = 0; i < 40; i += 1) {
    await sleep(2000);
    const rows = await db
      .select({
        id: incidents.id,
        status: incidents.status,
        verdict: incidents.verdict,
        correlationKey: incidents.correlationKey,
      })
      .from(incidents)
      .where(
        sql`${incidents.correlationKey} in (${sql.join([sql`${EXFIL_KEY}`, sql`${OWNER_KEY}`], sql`, `)})`,
      );
    const ex = rows.find((r) => r.correlationKey === EXFIL_KEY);
    const ow = rows.find((r) => r.correlationKey === OWNER_KEY);
    if (ex?.status === "triaged" && ow?.status === "triaged") {
      exfil = { id: ex.id, status: ex.status, verdict: ex.verdict as Verdict | null };
      owner = { id: ow.id, status: ow.status, verdict: ow.verdict as Verdict | null };
      break;
    }
  }

  // Count distinct incidents this night produced (grouping separation check).
  const nightIncidents = await db
    .select({ id: incidents.id, correlationKey: incidents.correlationKey })
    .from(incidents)
    .where(
      sql`${incidents.correlationKey} in (${sql.join(
        ALL_CORR_KEYS.map((k) => sql`${k}`),
        sql`, `,
      )})`,
    );
  const distinctKeys = new Set(nightIncidents.map((r) => r.correlationKey));

  // Alerts folded into the exfil incident (grouping-ratio check).
  let exfilAlertCount = 0;
  if (exfil) {
    const [{ count }] = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(incidentAlerts)
      .where(eq(incidentAlerts.incidentId, exfil.id));
    exfilAlertCount = count;
  }

  const exfilLedger = exfil ? await readLedger(exfil.id) : [];
  const ownerLedger = owner ? await readLedger(owner.id) : [];

  await queue.close();
  await ingestWorker.close();
  await fusionWorker.close();
  await correlationWorker.close();
  await triageWorker.close();
  await counter.close();
  await correlator.close();
  await provider.close();
  await closeDb();

  // --- Assertions ---
  const checks: Array<[string, boolean]> = [
    ["exfil incident exists", exfil !== null],
    ["owner incident exists", owner !== null],
    [
      "exfil is dangerous (critical|suspicious)",
      exfil?.verdict?.verdict === "critical" || exfil?.verdict?.verdict === "suspicious",
    ],
    [
      "owner login NOT escalated to critical",
      owner?.verdict != null && owner.verdict.verdict !== "critical",
    ],
    ["exfil folded >1 alert into one incident", exfilAlertCount > 1],
    [
      "noise stays separate (>=3 distinct incidents this night)",
      distinctKeys.size >= 3,
    ],
    ["exfil ledger has context_gathered", exfilLedger.some((e) => e.action === "triage.context_gathered")],
    ["exfil ledger has triage.verdict", exfilLedger.some((e) => e.action === "triage.verdict")],
    ["exfil ledger seq is ordered", exfilLedger.every((e, i) => e.seq === i)],
    ["owner ledger has triage.verdict", ownerLedger.some((e) => e.action === "triage.verdict")],
    ["owner ledger seq is ordered", ownerLedger.every((e, i) => e.seq === i)],
  ];

  console.log("\n[smoke] results:");
  for (const [label, ok] of checks) {
    console.log(`  ${ok ? "✓" : "✗"} ${label}`);
  }
  console.log(
    `\n[smoke] exfil=${exfil?.verdict?.verdict ?? "?"}/${exfil?.verdict?.confidence ?? "?"} ` +
      `(${exfilAlertCount} alerts)  owner=${owner?.verdict?.verdict ?? "?"}/${owner?.verdict?.confidence ?? "?"}  ` +
      `distinct incidents=${distinctKeys.size}`,
  );

  const pass = checks.every(([, ok]) => ok);
  console.log(pass ? "\nPASS: end-to-end pipeline produces the expected incidents and verdicts" : "\nFAIL");
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
