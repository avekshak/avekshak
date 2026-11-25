import { ingestQueue, startIngestWorker } from "../../pipeline/ingestQueue.js";
import { startSyslogListener } from "./listener.js";

const UDP_PORT = Number(process.env.SYSLOG_UDP_PORT ?? 5514);
const TCP_PORT = Number(process.env.SYSLOG_TCP_PORT ?? 5514);

async function main() {
  const worker = startIngestWorker();
  const queue = ingestQueue();

  const listener = await startSyslogListener({
    udpPort: UDP_PORT,
    tcpPort: TCP_PORT,
    queue,
    onSkip: (line) =>
      console.warn("[syslog] skipped malformed line:", JSON.stringify(line.slice(0, 120))),
  });

  const shutdown = async () => {
    console.log("\n[syslog] shutting down...");
    await listener.close();
    await queue.close();
    await worker.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("[syslog] fatal:", err);
  process.exit(1);
});
