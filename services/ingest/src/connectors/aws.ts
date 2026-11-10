import { readdir, readFile } from "fs/promises";
import { join } from "path";
import { createQueue } from "@avekshak/queue";
import { normalizeCloudTrail, normalizeGuardDuty } from "../normalize/aws.js";
import type { NormalizedEvent } from "@avekshak/schema";

const AWS_FIXTURES_DIR = process.env.AWS_FIXTURES_DIR ?? "./fixtures/aws";
const AWS_POLL_MS = Number(process.env.AWS_POLL_MS ?? 60_000);

const queue = createQueue<NormalizedEvent>("ingest");

// Track processed files so we don't re-ingest on re-poll
const processed = new Set<string>();

interface CloudTrailFile {
  Records?: unknown[];
}

interface GuardDutyFile {
  Findings?: unknown[];
}

async function ingestFile(filePath: string): Promise<number> {
  const content = await readFile(filePath, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    console.warn(`[aws] skipping unparseable file: ${filePath}`);
    return 0;
  }

  let ingested = 0;

  // CloudTrail format: { Records: [...] }
  const ct = parsed as CloudTrailFile;
  if (Array.isArray(ct.Records)) {
    for (const record of ct.Records) {
      const event = normalizeCloudTrail(record);
      if (!event) {
        console.warn("[aws:cloudtrail] dropped malformed record");
        continue;
      }
      await queue.enqueue("cloudtrail", event);
      ingested++;
    }
    return ingested;
  }

  // GuardDuty format: { Findings: [...] }
  const gd = parsed as GuardDutyFile;
  if (Array.isArray(gd.Findings)) {
    for (const finding of gd.Findings) {
      const event = normalizeGuardDuty(finding);
      if (!event) {
        console.warn("[aws:guardduty] dropped malformed finding");
        continue;
      }
      await queue.enqueue("guardduty", event);
      ingested++;
    }
    return ingested;
  }

  console.warn(`[aws] unrecognised file format: ${filePath}`);
  return 0;
}

async function poll(): Promise<void> {
  let entries: string[];
  try {
    entries = await readdir(AWS_FIXTURES_DIR);
  } catch {
    // Directory doesn't exist yet — silently skip
    return;
  }

  const jsonFiles = entries.filter((f) => f.endsWith(".json"));
  let total = 0;

  for (const file of jsonFiles) {
    const filePath = join(AWS_FIXTURES_DIR, file);
    if (processed.has(filePath)) continue;
    processed.add(filePath);

    const count = await ingestFile(filePath);
    total += count;
  }

  if (total > 0) {
    console.log(`[aws] ingested ${total} events from ${AWS_FIXTURES_DIR}`);
  }
}

export function startAwsConnector(): void {
  console.log(`[aws] watching ${AWS_FIXTURES_DIR} every ${AWS_POLL_MS}ms`);
  poll().catch(console.error);
  setInterval(() => poll().catch(console.error), AWS_POLL_MS);
}
