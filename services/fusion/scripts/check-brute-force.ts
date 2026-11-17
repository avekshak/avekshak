import { randomUUID } from "node:crypto";
import { getDb, events, alerts, closeDb } from "@avekshak/db";
import { sql } from "drizzle-orm";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { NormalizedEvent } from "@avekshak/schema";
import { loadRulesFromDir } from "../src/rules/loader.js";
import { evaluate } from "../src/rules/evaluator.js";
import { syncRules, promoteAlert } from "../src/pipeline/alertWriter.js";
import { WindowCounter } from "../src/pipeline/windowCounter.js";

/**
 * Integration check for 2.4: feed failed-login events from one IP through the
 * window counter + brute-force rule. 5 events in the window must produce
 * exactly ONE brute-force alert; 4 events must produce NONE.
 */

const DETECTIONS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../detections",
);

function failedLogin(ip: string, ts: string): NormalizedEvent {
  return {
    id: randomUUID(),
    ts,
    source: "syslog",
    category: "authentication",
    action: "login_failed",
    outcome: "failure",
    severity: 40,
    actor: { user: "root", ip },
    target: { host: "db-prod-1" },
    raw: {},
  };
}

async function insertEvent(ev: NormalizedEvent): Promise<void> {
  await getDb()
    .insert(events)
    .values({
      id: ev.id,
      ts: new Date(ev.ts),
      source: ev.source,
      category: ev.category,
      action: ev.action,
      outcome: ev.outcome,
      severity: ev.severity,
      actorUser: ev.actor.user ?? null,
      actorIp: ev.actor.ip ?? null,
      targetHost: ev.target.host ?? null,
      raw: ev.raw,
    })
    .onConflictDoNothing({ target: events.id });
}

/** Drive a burst of failed logins from one IP; return brute-force alert count. */
async function runBurst(
  ip: string,
  n: number,
  rules: Awaited<ReturnType<typeof loadRulesFromDir>>,
  counter: WindowCounter,
): Promise<number> {
  let bruteForceAlerts = 0;
  const base = Date.parse("2026-06-01T02:00:00.000Z");
  for (let i = 0; i < n; i += 1) {
    // Spread events across ~4 minutes, all inside the 300s window.
    const ts = new Date(base + i * 40_000).toISOString();
    const ev = failedLogin(ip, ts);
    await insertEvent(ev);
    const { windowCandidates } = evaluate(ev, rules);
    for (const rule of windowCandidates) {
      const tripped = await counter.record(ev, rule);
      if (tripped) {
        const isNew = await promoteAlert(ev, rule);
        if (isNew) bruteForceAlerts += 1;
      }
    }
  }
  return bruteForceAlerts;
}

async function main() {
  const db = getDb();
  const rules = await loadRulesFromDir(DETECTIONS_DIR);
  await syncRules(rules);

  const counter = new WindowCounter();
  // Fresh Redis window keys for both test IPs.
  const redisAny = counter as unknown as { redis: import("ioredis").Redis };
  await redisAny.redis.del(
    "win:brute-force-logins:198.51.100.5:" + Math.floor(Date.parse("2026-06-01T02:00:00.000Z") / 300000),
  );
  await redisAny.redis.del(
    "win:brute-force-logins:198.51.100.6:" + Math.floor(Date.parse("2026-06-01T02:00:00.000Z") / 300000),
  );

  // Clean slate.
  await db.execute(sql`delete from ${alerts} where rule_id = 'brute-force-logins'`);
  await db.execute(sql`delete from ${events} where actor_ip in ('198.51.100.5','198.51.100.6')`);

  // IP A: 5 failures → expect exactly 1 brute-force alert.
  const fiveResult = await runBurst("198.51.100.5", 5, rules, counter);
  // IP B: 4 failures → expect 0.
  const fourResult = await runBurst("198.51.100.6", 4, rules, counter);

  const rows = (await db.execute(
    sql`select actor_ip, count(*)::int as n from ${alerts} where rule_id = 'brute-force-logins' group by actor_ip order by actor_ip`,
  )) as unknown as Array<{ actor_ip: string; n: number }>;

  console.log("5-burst brute-force alerts created:", fiveResult);
  console.log("4-burst brute-force alerts created:", fourResult);
  console.log("brute-force alert rows by ip:", rows);

  await counter.close();
  await closeDb();

  const fiveOk = fiveResult === 1;
  const fourOk = fourResult === 0;
  const dbOk =
    rows.length === 1 &&
    rows[0].actor_ip === "198.51.100.5" &&
    rows[0].n === 1;
  const pass = fiveOk && fourOk && dbOk;
  console.log(
    pass
      ? "PASS: 5 failures → 1 brute-force alert; 4 → none"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
