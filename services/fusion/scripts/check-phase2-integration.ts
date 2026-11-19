import { randomUUID } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getDb, events, alerts, closeDb } from "@avekshak/db";
import { sql } from "drizzle-orm";
import type { NormalizedEvent } from "@avekshak/schema";
import { ingestQueue, startIngestWorker } from "../../ingest/src/pipeline/ingestQueue.js";
import { loadRulesFromDir } from "../src/rules/loader.js";
import { syncRules } from "../src/pipeline/alertWriter.js";
import { WindowCounter } from "../src/pipeline/windowCounter.js";
import { startFusionWorker } from "../src/pipeline/detectQueue.js";

/**
 * Phase 2 integration gate. Events are enqueued onto the REAL ingest queue;
 * the ingest worker persists them and forwards to the detect queue; the fusion
 * worker evaluates rules and promotes alerts — the whole thing running live
 * through BullMQ/Redis/Postgres. We feed a known-malicious sequence and assert
 * the expected alerts appear, in real time, with no manual promotion.
 */

const DETECTIONS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../detections",
);

const BAD_IP = "203.0.113.9";

function failedLogin(ts: string): NormalizedEvent {
  return {
    id: randomUUID(),
    ts,
    source: "syslog",
    category: "authentication",
    action: "login_failed",
    outcome: "failure",
    severity: 40,
    actor: { user: "root", ip: BAD_IP },
    target: { host: "db-prod-1" },
    raw: {},
  };
}

function exfilFinding(): NormalizedEvent {
  return {
    id: randomUUID(),
    ts: "2026-06-01T02:05:00.000Z",
    source: "aws",
    category: "cloud",
    action: "Exfiltration:S3/ObjectRead.Unusual",
    outcome: "unknown",
    severity: 80,
    actor: {},
    target: { resource: "S3Bucket" },
    location: { city: "eu-west-1" },
    raw: {},
  };
}

async function main() {
  const db = getDb();
  const rules = await loadRulesFromDir(DETECTIONS_DIR);
  await syncRules(rules);

  // Clean slate for the identities this check touches.
  await db.execute(sql`delete from ${alerts}`);
  await db.execute(
    sql`delete from ${events} where actor_ip = ${BAD_IP} or action like 'Exfiltration%'`,
  );
  const counter = new WindowCounter();
  const redis = (counter as unknown as { redis: import("ioredis").Redis }).redis;
  const bucket = Math.floor(Date.parse("2026-06-01T02:00:00.000Z") / 300000);
  await redis.del(`win:brute-force-logins:${BAD_IP}:${bucket}`);

  // Start BOTH workers — the live pipeline.
  const ingestWorker = startIngestWorker();
  const fusionWorker = startFusionWorker(rules, counter);
  const queue = ingestQueue();

  // Malicious sequence: 5 failed root logins from one bad IP (within window) +
  // one S3 exfiltration finding. Enqueue onto the ingest queue only.
  const base = Date.parse("2026-06-01T02:00:00.000Z");
  for (let i = 0; i < 5; i += 1) {
    await queue.enqueue("syslog", failedLogin(new Date(base + i * 40_000).toISOString()));
  }
  await queue.enqueue("aws", exfilFinding());

  // Let the two-stage pipeline drain.
  await sleep(2500);

  const alertRows = (await db.execute(
    sql`select rule_id, count(*)::int as n from ${alerts} group by rule_id order by rule_id`,
  )) as unknown as Array<{ rule_id: string; n: number }>;
  const eventCount = (
    (await db.execute(
      sql`select count(*)::int as n from ${events} where actor_ip = ${BAD_IP} or action like 'Exfiltration%'`,
    )) as unknown as Array<{ n: number }>
  )[0].n;

  console.log("events persisted:", eventCount);
  console.log("alerts by rule:", alertRows);

  await queue.close();
  await ingestWorker.close();
  await fusionWorker.close();
  await counter.close();
  await closeDb();

  const byRule = new Map(alertRows.map((r) => [r.rule_id, r.n]));
  // Expected from the malicious sequence:
  //  - auth-failed-login: 1 (5 failures collapse to one in-window alert)
  //  - known-bad-ip: 1 (same collapse)
  //  - brute-force-logins: 1 (fires once at the 5th)
  //  - cloud-exfiltration-finding: 1 (the S3 finding)
  //  - high-severity-source: 1 (exfil severity 80 ≥ 80)
  const pass =
    eventCount === 6 &&
    byRule.get("auth-failed-login") === 1 &&
    byRule.get("known-bad-ip") === 1 &&
    byRule.get("brute-force-logins") === 1 &&
    byRule.get("cloud-exfiltration-finding") === 1 &&
    byRule.get("high-severity-source") === 1;
  console.log(
    pass
      ? "PASS: live ingest→detect pipeline produced the expected alerts"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
