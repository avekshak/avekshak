import { v5 as uuidv5 } from "uuid";
import { normalizeAws } from "../../normalize/aws.js";
import type { TypedQueue } from "@avekshak/queue";
import type { NormalizedEvent } from "@avekshak/schema";

const AWS_NS = "9b2c1d4e-5f6a-5b7c-8d9e-0a1b2c3d4e5f";

export interface AwsIngestResult {
  enqueued: number;
  skipped: number;
}

export function extractAwsRecords(parsed: unknown): unknown[] {
  if (Array.isArray(parsed)) return parsed;
  if (parsed !== null && typeof parsed === "object") {
    const o = parsed as Record<string, unknown>;
    if (Array.isArray(o.Records)) return o.Records;
    return [parsed];
  }
  return [];
}

function stableKey(rec: unknown): string | undefined {
  if (rec === null || typeof rec !== "object") return undefined;
  const o = rec as Record<string, unknown>;
  const candidate =
    (o.eventID as string | undefined) ??
    (o.id as string | undefined) ??
    (o.arn as string | undefined);
  return typeof candidate === "string" ? candidate : undefined;
}

export async function processAwsRecords(
  records: unknown[],
  queue: TypedQueue<NormalizedEvent>,
  onSkip?: (index: number) => void,
): Promise<AwsIngestResult> {
  let enqueued = 0;
  let skipped = 0;

  for (let i = 0; i < records.length; i += 1) {
    const rec = records[i];
    const key = stableKey(rec);
    const id = key ? uuidv5(`aws:${key}`, AWS_NS) : undefined;
    const ev = normalizeAws(rec, id);
    if (ev === null) {
      skipped += 1;
      onSkip?.(i);
      continue;
    }
    await queue.enqueue("aws", ev);
    enqueued += 1;
  }

  return { enqueued, skipped };
}
