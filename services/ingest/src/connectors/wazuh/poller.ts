import { v5 as uuidv5 } from "uuid";
import { normalizeWazuh } from "../../normalize/wazuh.js";
import type { TypedQueue } from "@avekshak/queue";
import type { NormalizedEvent } from "@avekshak/schema";

/** Namespace for deriving stable event ids from Wazuh doc _ids. */
const WAZUH_NS = "6f1e7b9a-2c3d-4e5f-8a9b-0c1d2e3f4a5b";

/** Shape of an Elasticsearch _search response (subset). */
export interface EsSearchResponse {
  hits?: {
    hits?: Array<{
      _id?: string;
      _source?: unknown;
    }>;
  };
}

export interface WazuhPollResult {
  /** Number of events enqueued (excludes skipped/malformed). */
  enqueued: number;
  /** Number of hits that failed normalization and were skipped. */
  skipped: number;
}

/**
 * Pure processor: given an ES _search response, normalize each hit and enqueue
 * valid events. Deterministic id (UUIDv5 of the hit _id) means re-polling the
 * same document enqueues an event with the same id, which writeEvent dedupes.
 * Never throws on a bad hit — it is counted as skipped.
 */
export async function processWazuhResponse(
  res: EsSearchResponse,
  queue: TypedQueue<NormalizedEvent>,
  onSkip?: (docId: string | undefined) => void,
): Promise<WazuhPollResult> {
  const hits = res.hits?.hits ?? [];
  let enqueued = 0;
  let skipped = 0;

  for (const hit of hits) {
    const stableId = hit._id ? uuidv5(`wazuh:${hit._id}`, WAZUH_NS) : undefined;
    const ev = normalizeWazuh(hit._source, stableId);
    if (ev === null) {
      skipped += 1;
      onSkip?.(hit._id);
      continue;
    }
    await queue.enqueue("wazuh", ev);
    enqueued += 1;
  }

  return { enqueued, skipped };
}
