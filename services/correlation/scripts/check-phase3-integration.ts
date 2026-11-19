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
  closeDb,
} from "@avekshak/db";
import { sql } from "drizzle-orm";
import type { NormalizedEvent } from "@avekshak/schema";
import { ingestQueue, startIngestWorker } from "../../ingest/src/pipeline/ingestQueue.js";
import { loadRulesFromDir } from "../../fusion/src/rules/loader.js";
import { syncRules } from "../../fusion/src/pipeline/alertWriter.js";
import { WindowCounter } from "../../fusion/src/pipeline/windowCounter.js";
import { startFusionWorker } from "../../fusion/src/pipeline/detectQueue.js";
import { Correlator } from "../src/correlate/correlator.js";
import { startCorrelationWorker } from "../src/correlate/queue.js";

/**
 * Phase 3 integration gate. The FULL upstream pipeline runs live through
 * BullMQ/Redis/Postgres: ingest → detect → correlate. We simulate an attack —
 * a single attacker IP hammering one host across the correlation window — and
 * assert every resulting alert collapses into ONE incident, while unrelated
 * "noise" from other identities opens its own separate incidents. The point of
 * the product is the grouping ratio: many alerts → far fewer incidents.
 */

const DETECTIONS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../detections",
);

const ATTACKER_IP = "198.51.100.77";
const ATTACKER_HOST = "db-prod-7";
// Noise: three unrelated identities that must NOT fold into the attack incident.
const NOISE = [
  { ip: "192.0.2.11", host: "web-1", user: "alice" },
  { ip: "192.0.2.12", host: "web-2", user: "bob" },
  { ip: "192.0.2.13", host: "web-3", user: "carol" },
];

function failedLogin(ip: string, host: string, user: string, ts: string): NormalizedEvent {
  return {
    id: randomUUID(),
    ts,
    source: "syslog",
    category: "authentication",
    action: "login_failed",
    outcome: "failure",
    severity: 40,
    actor: { user, ip },
    target: { host },
    raw: {},
  };
}

async function main() {
  const db = getDb();
  const rules = await loadRulesFromDir(DETECTIONS_DIR);
  await syncRules(rules);

  const allIps = [ATTACKER_IP, ...NOISE.map((n) => n.ip)];
  const noiseIps = NOISE.map((n) => n.ip);
  // Comma-separated bound-parameter lists for SQL `in (...)` clauses.
  const ipList = sql.join(allIps.map((ip) => sql`${ip}`), sql`, `);
  const corrKeyList = sql.join(allIps.map((ip) => sql`${"ip:" + ip}`), sql`, `);
  const noiseIpList = sql.join(noiseIps.map((ip) => sql`${ip}`), sql`, `);

  // Clean slate for every identity this check touches (order respects FKs).
  await db.execute(
    sql`delete from ${incidentAlerts} where alert_id in (select id from ${alerts} where actor_ip in (${ipList}))`,
  );
  await db.execute(
    sql`delete from ${incidents} where correlation_key in (${corrKeyList})`,
  );
  await db.execute(sql`delete from ${alerts} where actor_ip in (${ipList})`);
  await db.execute(sql`delete from ${events} where actor_ip in (${ipList})`);

  const counter = new WindowCounter();
  const correlator = new Correlator();
  const orRedis = (correlator as unknown as { redis: import("ioredis").Redis }).redis;
  // Clear any stale active-correlation keys.
  await orRedis.del(...allIps.map((ip) => `corr:ip:${ip}`));

  // Start the WHOLE pipeline: ingest → detect → correlate.
  const ingestWorker = startIngestWorker();
  const fusionWorker = startFusionWorker(rules, counter);
  const correlationWorker = startCorrelationWorker(correlator);
  const queue = ingestQueue();

  // The attack: same IP + host, spread every 6 minutes across 30 minutes.
  // 6-minute spacing crosses the 5-minute fusion dedupe bucket, so each failed
  // login promotes a DISTINCT alert — 5 attack alerts per rule — yet all land
  // inside the 30-minute correlation window, so they must share one incident.
  const base = Date.parse("2026-06-01T03:00:00.000Z");
  const ATTACK_COUNT = 5;
  for (let i = 0; i < ATTACK_COUNT; i += 1) {
    const ts = new Date(base + i * 6 * 60_000).toISOString();
    await queue.enqueue("syslog", failedLogin(ATTACKER_IP, ATTACKER_HOST, "root", ts));
  }

  // The noise: one failed login from each unrelated identity.
  for (const n of NOISE) {
    await queue.enqueue(
      "syslog",
      failedLogin(n.ip, n.host, n.user, "2026-06-01T03:03:00.000Z"),
    );
  }

  // Let the three-stage pipeline drain.
  await sleep(4000);

  // How many distinct alerts did the attacker generate, and how many incidents?
  const attackAlertCount = (
    (await db.execute(
      sql`select count(*)::int as n from ${alerts} where actor_ip = ${ATTACKER_IP}`,
    )) as unknown as Array<{ n: number }>
  )[0].n;

  const attackIncidentRows = (await db.execute(
    sql`select distinct i.id
          from ${incidents} i
          join ${incidentAlerts} ia on ia.incident_id = i.id
          join ${alerts} a on a.id = ia.alert_id
         where a.actor_ip = ${ATTACKER_IP}`,
  )) as unknown as Array<{ id: string }>;

  const attackIncidentId = attackIncidentRows[0]?.id;
  const linkedToAttack = attackIncidentId
    ? (
        (await db.execute(
          sql`select count(*)::int as n from ${incidentAlerts} where incident_id = ${attackIncidentId}`,
        )) as unknown as Array<{ n: number }>
      )[0].n
    : 0;

  // Each noise identity must have its OWN incident, separate from the attack.
  const noiseIncidentRows = (await db.execute(
    sql`select distinct i.id
          from ${incidents} i
          join ${incidentAlerts} ia on ia.incident_id = i.id
          join ${alerts} a on a.id = ia.alert_id
         where a.actor_ip in (${noiseIpList})`,
  )) as unknown as Array<{ id: string }>;
  const noiseIncidentIds = new Set(noiseIncidentRows.map((r) => r.id));

  // Grouping ratio across the whole run.
  const totalAlerts = attackAlertCount + NOISE.length; // attacker alerts counted below
  const totalIncidents = attackIncidentRows.length + noiseIncidentIds.size;

  console.log("attacker alerts generated:", attackAlertCount);
  console.log("attacker incidents:", attackIncidentRows.length);
  console.log("alerts linked to attack incident:", linkedToAttack);
  console.log("noise incidents (distinct):", noiseIncidentIds.size);
  console.log(
    `grouping ratio: ${attackAlertCount} attack alerts → ${attackIncidentRows.length} incident`,
  );

  await queue.close();
  await ingestWorker.close();
  await fusionWorker.close();
  await correlationWorker.close();
  await counter.close();
  await correlator.close();
  await closeDb();

  const pass =
    // Attacker produced several distinct alerts (>1 proves no over-dedupe)...
    attackAlertCount >= ATTACK_COUNT &&
    // ...all folded into exactly ONE incident...
    attackIncidentRows.length === 1 &&
    linkedToAttack === attackAlertCount &&
    // ...and the three noise identities stayed as three separate incidents,
    // none of them the attack incident.
    noiseIncidentIds.size === NOISE.length &&
    !noiseIncidentIds.has(attackIncidentId) &&
    // The grouping ratio must actually reduce the count.
    totalIncidents < totalAlerts;

  console.log(
    pass
      ? "PASS: full pipeline groups a simulated attack into one incident; noise stays separate"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
