import { readFile } from "node:fs/promises";
import { setTimeout as sleep } from "node:timers/promises";
import {
  extractAwsRecords,
  processAwsRecords,
} from "./reader.js";
import { ingestQueue, startIngestWorker } from "../../pipeline/ingestQueue.js";

/**
 * Parses a file's contents into a list of records. Tries whole-file JSON first
 * (array, CloudTrail {Records:[]}, or single object); falls back to NDJSON
 * (one JSON object per line) when the whole-file parse fails.
 */
function parseFile(contents: string): unknown[] {
  const trimmed = contents.trim();
  if (trimmed.length === 0) return [];
  try {
    return extractAwsRecords(JSON.parse(trimmed));
  } catch {
    // NDJSON fallback.
    const out: unknown[] = [];
    for (const line of trimmed.split("\n")) {
      const l = line.trim();
      if (l.length === 0) continue;
      try {
        out.push(JSON.parse(l));
      } catch {
        // skip unparseable line
      }
    }
    return out;
  }
}

async function main() {
  const paths = process.argv.slice(2);
  if (paths.length === 0) {
    console.error("usage: aws <file.json> [more files...]");
    process.exit(2);
  }

  const worker = startIngestWorker();
  const queue = ingestQueue();

  let totalEnq = 0;
  let totalSkip = 0;
  for (const path of paths) {
    const contents = await readFile(path, "utf8");
    const records = parseFile(contents);
    const result = await processAwsRecords(records, queue, (i) =>
      console.warn(`[aws] skipped record ${i} in ${path}`),
    );
    totalEnq += result.enqueued;
    totalSkip += result.skipped;
    console.log(
      `[aws] ${path}: enqueued=${result.enqueued} skipped=${result.skipped}`,
    );
  }

  // Let the worker drain, then shut down. (File ingest is one-shot.)
  await sleep(1500);
  await queue.close();
  await worker.close();
  console.log(`[aws] done: enqueued=${totalEnq} skipped=${totalSkip}`);
  process.exit(0);
}

main().catch((err) => {
  console.error("[aws] fatal:", err);
  process.exit(1);
});
