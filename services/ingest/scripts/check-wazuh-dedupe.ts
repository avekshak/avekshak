import http from "node:http";
import { setTimeout as sleep } from "node:timers/promises";
import { getDb, events, closeDb } from "@avekshak/db";
import { sql } from "drizzle-orm";
import { ingestQueue, startIngestWorker } from "../src/pipeline/ingestQueue.js";
import { processWazuhResponse, type EsSearchResponse } from "../src/connectors/wazuh/poller.js";

const fixture: EsSearchResponse = {
  hits: {
    hits: [
      {
        _id: "wz-1",
        _source: {
          timestamp: "2026-06-01T02:00:00.000Z",
          rule: { level: 12, groups: ["authentication_failed"] },
          agent: { name: "db-prod-1", ip: "10.0.0.20" },
          data: { srcip: "203.0.113.9", srcuser: "root" },
        },
      },
      {
        _id: "wz-2",
        _source: {
          timestamp: "2026-06-01T02:00:05.000Z",
          rule: { level: 5, groups: ["syscheck"] },
          agent: { name: "db-prod-1", ip: "10.0.0.20" },
        },
      },
    ],
  },
};

async function countWazuh(): Promise<number> {
  const rows = await getDb().execute(
    sql`select count(*)::int as n from ${events} where source = 'wazuh'`,
  );
  return (rows as unknown as Array<{ n: number }>)[0].n;
}

async function main() {
  const server = http.createServer((_req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(fixture));
  });
  await new Promise<void>((r) => server.listen(0, r));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  console.log(`stub ES on :${port}`);

  await getDb().execute(sql`delete from ${events} where source = 'wazuh'`);

  const worker = startIngestWorker();
  const queue = ingestQueue();

  async function pollOnce(): Promise<void> {
    const r = await fetch(`http://127.0.0.1:${port}/wazuh-alerts/_search`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const body = (await r.json()) as EsSearchResponse;
    const result = await processWazuhResponse(body, queue);
    console.log("poll result:", result);
  }

  await pollOnce();
  await sleep(1500);
  const afterFirst = await countWazuh();
  console.log("rows after first poll:", afterFirst);

  await pollOnce();
  await sleep(1500);
  const afterSecond = await countWazuh();
  console.log("rows after second poll:", afterSecond);

  await queue.close();
  await worker.close();
  server.close();
  await closeDb();

  const pass = afterFirst === 2 && afterSecond === 2;
  console.log(pass ? "PASS: dedupe holds (2 → 2)" : "FAIL");
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
