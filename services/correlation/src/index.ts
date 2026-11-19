import { closeDb } from "@avekshak/db";
import { Correlator } from "./correlate/correlator.js";
import { startCorrelationWorker } from "./correlate/queue.js";

async function main() {
  const correlator = new Correlator();
  const worker = startCorrelationWorker(correlator);
  console.log("[correlation] worker running");

  const shutdown = async () => {
    console.log("[correlation] shutting down");
    await worker.close();
    await correlator.close();
    await closeDb();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("[correlation] fatal:", err);
  process.exit(1);
});
