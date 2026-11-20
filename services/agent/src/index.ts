import { closeDb } from "@avekshak/db";
import { createProvider } from "./llm/index.js";
import { startTriageWorker } from "./triage/queue.js";

async function main() {
  const provider = createProvider();
  const worker = startTriageWorker(provider);
  console.log(`[agent] triage worker running (provider: ${provider.name})`);

  const shutdown = async () => {
    console.log("[agent] shutting down");
    await worker.close();
    await provider.close();
    await closeDb();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("[agent] fatal:", err);
  process.exit(1);
});
