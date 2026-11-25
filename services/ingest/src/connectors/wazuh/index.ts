import { processWazuhResponse, type EsSearchResponse } from "./poller.js";
import { ingestQueue, startIngestWorker } from "../../pipeline/ingestQueue.js";

const ES_URL = process.env.WAZUH_ES_URL ?? "http://localhost:9200";
const ES_INDEX = process.env.WAZUH_ES_INDEX ?? "wazuh-alerts-*";
const POLL_MS = Number(process.env.WAZUH_POLL_MS ?? 10000);
const PAGE_SIZE = Number(process.env.WAZUH_PAGE_SIZE ?? 500);

/**
 * Fetches alert docs newer than `since` from an Elasticsearch-compatible
 * index, sorted ascending by timestamp.
 */
async function fetchSince(since: string | null): Promise<EsSearchResponse> {
  const query = since
    ? { range: { timestamp: { gt: since } } }
    : { match_all: {} };

  const body = {
    size: PAGE_SIZE,
    sort: [{ timestamp: "asc" }],
    query,
  };

  const res = await fetch(`${ES_URL}/${ES_INDEX}/_search`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`Elasticsearch ${res.status}: ${await res.text()}`);
  }
  return (await res.json()) as EsSearchResponse;
}

function newestTimestamp(res: EsSearchResponse): string | null {
  const hits = res.hits?.hits ?? [];
  let newest: string | null = null;
  for (const h of hits) {
    const ts = (h._source as { timestamp?: string } | undefined)?.timestamp;
    if (typeof ts === "string" && (newest === null || ts > newest)) newest = ts;
  }
  return newest;
}

async function main() {
  const worker = startIngestWorker();
  const queue = ingestQueue();
  let cursor: string | null = null;
  let running = true;

  console.log(`[wazuh] polling ${ES_URL}/${ES_INDEX} every ${POLL_MS}ms`);

  const shutdown = async () => {
    running = false;
    console.log("\n[wazuh] shutting down...");
    await queue.close();
    await worker.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  while (running) {
    try {
      const res = await fetchSince(cursor);
      const result = await processWazuhResponse(res, queue, (id) =>
        console.warn("[wazuh] skipped malformed doc:", id),
      );
      const newest = newestTimestamp(res);
      if (newest !== null) cursor = newest;
      if (result.enqueued > 0 || result.skipped > 0) {
        console.log(
          `[wazuh] enqueued=${result.enqueued} skipped=${result.skipped} cursor=${cursor}`,
        );
      }
    } catch (err) {
      console.error("[wazuh] poll error:", (err as Error).message);
    }
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

main().catch((err) => {
  console.error("[wazuh] fatal:", err);
  process.exit(1);
});
