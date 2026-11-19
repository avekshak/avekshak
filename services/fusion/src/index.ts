import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadRulesFromDir } from "./rules/loader.js";
import { syncRules } from "./pipeline/alertWriter.js";
import { WindowCounter } from "./pipeline/windowCounter.js";
import { startFusionWorker } from "./pipeline/detectQueue.js";
import { closeDb } from "@avekshak/db";

const DETECTIONS_DIR =
  process.env.DETECTIONS_DIR ??
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../detections");

async function main() {
  const rules = await loadRulesFromDir(DETECTIONS_DIR);
  await syncRules(rules);
  console.log(`[fusion] loaded ${rules.length} rules from ${DETECTIONS_DIR}`);

  const counter = new WindowCounter();
  const worker = startFusionWorker(rules, counter);
  console.log("[fusion] detection worker running");

  const shutdown = async () => {
    console.log("[fusion] shutting down");
    await worker.close();
    await counter.close();
    await closeDb();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("[fusion] fatal:", err);
  process.exit(1);
});
