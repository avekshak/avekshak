import { createWorker } from "@avekshak/queue";
import { NormalizedEventSchema } from "@avekshak/schema";
import type { NormalizedEvent } from "@avekshak/schema";
import { loadRules } from "./rule-loader.js";
import { evaluateRules } from "./evaluator.js";
import { promoteAlert } from "./promoter.js";
import { evaluateThreshold } from "./threshold.js";
import type { Rule } from "./rule-schema.js";

let rules: Rule[] = [];

export async function startFusionWorker(rulesDir?: string): Promise<void> {
  rules = await loadRules(rulesDir);

  createWorker<NormalizedEvent>("detect", async (job) => {
    const parsed = NormalizedEventSchema.safeParse(job.data);
    if (!parsed.success) {
      console.error("[fusion] invalid event:", parsed.error.flatten());
      return;
    }

    const event = parsed.data;

    // Evaluate single-event rules
    const matched = evaluateRules(event, rules);
    for (const rule of matched) {
      await promoteAlert(event, rule);
    }

    // Evaluate threshold (windowed) rules
    const thresholdRules = rules.filter((r) => r.threshold);
    for (const rule of thresholdRules) {
      await evaluateThreshold(event, rule);
    }
  });

  console.log("[fusion] worker started");
}
