import dgram from "node:dgram";
import http from "node:http";
import { setTimeout as sleep } from "node:timers/promises";
import { getDb, events, closeDb } from "@avekshak/db";
import { sql } from "drizzle-orm";
import { ingestQueue, startIngestWorker } from "../src/pipeline/ingestQueue.js";
import { startSyslogListener } from "../src/connectors/syslog/listener.js";
import {
  processWazuhResponse,
  type EsSearchResponse,
} from "../src/connectors/wazuh/poller.js";
import { processAwsRecords, extractAwsRecords } from "../src/connectors/aws/reader.js";
import { readFile } from "node:fs/promises";

const SYSLOG_UDP_PORT = 5516;

const wazuhFixture: EsSearchResponse = {
  hits: {
    hits: [
      {
        _id: "p1-wz-1",
        _source: {
          timestamp: "2026-06-01T02:00:00.000Z",
          rule: { level: 12, groups: ["authentication_failed"] },
          agent: { name: "db-prod-1", ip: "10.0.0.20" },
          data: { srcip: "203.0.113.9", srcuser: "root" },
        },
      },
      {
        _id: "p1-wz-2",
        _source: {
          timestamp: "2026-06-01T02:00:05.000Z",
          rule: { level: 5, groups: ["syscheck"] },
          agent: { name: "db-prod-1", ip: "10.0.0.20" },
        },
      },
      { _id: "p1-wz-bad", _source: { timestamp: "not-a-date" } },
    ],
  },
};

const syslogLines = [
  "<34>Jun  1 02:10:00 db-prod-1 sshd[1010]: Failed password for root from 203.0.113.9 port 2222 ssh2",
  "<38>Jun  1 02:10:05 db-prod-1 sshd[1011]: Accepted password for owner from 10.0.0.5 port 3333 ssh2",
  "",
];

async function countBySource(source: string): Promise<number> {
  const rows = await getDb().execute(
    sql`select count(*)::int as n from ${events} where source = ${source}`,
  );
  return (rows as unknown as Array<{ n: number }>)[0].n;
}

async function main() {
  await getDb().execute(
    sql`delete from ${events} where source in ('syslog','wazuh','aws')`,
  );

  const worker = startIngestWorker();
  const queue = ingestQueue();

  let syslogSkips = 0;
  const listener = await startSyslogListener({
    udpPort: SYSLOG_UDP_PORT,
    tcpPort: SYSLOG_UDP_PORT,
    host: "127.0.0.1",
    queue,
    onSkip: () => {
      syslogSkips += 1;
    },
  });
  const udp = dgram.createSocket("udp4");
  for (const line of syslogLines) {
    await new Promise<void>((r) =>
      udp.send(line, SYSLOG_UDP_PORT, "127.0.0.1", () => r()),
    );
  }
  udp.close();

  const server = http.createServer((_req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(wazuhFixture));
  });
  await new Promise<void>((r) => server.listen(0, r));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  const esRes = await fetch(`http://127.0.0.1:${port}/wazuh-alerts/_search`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  const wazuhResult = await processWazuhResponse(
    (await esRes.json()) as EsSearchResponse,
    queue,
  );

  const ctRaw = await readFile(
    new URL("../fixtures/cloudtrail.json", import.meta.url),
    "utf8",
  );
  const gdRaw = await readFile(
    new URL("../fixtures/guardduty.json", import.meta.url),
    "utf8",
  );
  const awsRecords = [
    ...extractAwsRecords(JSON.parse(ctRaw)),
    ...extractAwsRecords(JSON.parse(gdRaw)),
  ];
  const awsResult = await processAwsRecords(awsRecords, queue);

  console.log("syslog skips:", syslogSkips);
  console.log("wazuh result:", wazuhResult);
  console.log("aws result:", awsResult);

  await sleep(2000);

  const syslogRows = await countBySource("syslog");
  const wazuhRows = await countBySource("wazuh");
  const awsRows = await countBySource("aws");
  console.log(`rows  syslog=${syslogRows} wazuh=${wazuhRows} aws=${awsRows}`);

  await listener.close();
  server.close();
  await queue.close();
  await worker.close();
  await closeDb();

  const pass =
    syslogRows === 2 &&
    syslogSkips === 1 &&
    wazuhRows === 2 &&
    wazuhResult.skipped === 1 &&
    awsRows === 4 &&
    awsResult.skipped === 0;
  console.log(
    pass
      ? "PASS: all 3 connectors normalized concurrently; malformed skipped not crashed"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
