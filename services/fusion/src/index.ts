import { startFusionWorker } from "./worker.js";

const RULES_DIR = process.env.RULES_DIR ?? new URL("../rules", import.meta.url).pathname;

startFusionWorker(RULES_DIR).catch((err) => {
  console.error("[fusion] startup error:", err);
  process.exit(1);
});
