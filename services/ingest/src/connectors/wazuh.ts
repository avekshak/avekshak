import { createQueue } from "@avekshak/queue";
import { normalizeWazuh } from "../normalize/wazuh.js";
import type { NormalizedEvent } from "@avekshak/schema";

const WAZUH_URL = process.env.WAZUH_URL ?? "http://localhost:9200";
const WAZUH_INDEX = process.env.WAZUH_INDEX ?? "wazuh-alerts-*";
const WAZUH_USER = process.env.WAZUH_USER ?? "admin";
const WAZUH_PASSWORD = process.env.WAZUH_PASSWORD ?? "admin";
const WAZUH_POLL_MS = Number(process.env.WAZUH_POLL_MS ?? 30_000);

const queue = createQueue<NormalizedEvent>("ingest");

// Track the last seen timestamp to avoid re-ingesting the same hits
let lastSeen = new Date(Date.now() - WAZUH_POLL_MS).toISOString();

async function poll(): Promise<void> {
  const since = lastSeen;
  const now = new Date().toISOString();

  const body = JSON.stringify({
    query: {
      range: { timestamp: { gt: since, lte: now } },
    },
    size: 500,
    sort: [{ timestamp: { order: "asc" } }],
  });

  const auth = Buffer.from(`${WAZUH_USER}:${WAZUH_PASSWORD}`).toString("base64");

  let res: Response;
  try {
    res = await fetch(`${WAZUH_URL}/${WAZUH_INDEX}/_search`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${auth}`,
      },
      body,
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err) {
    console.warn("[wazuh] poll failed (will retry):", (err as Error).message);
    return;
  }

  if (!res.ok) {
    console.warn(`[wazuh] poll HTTP ${res.status} — will retry`);
    return;
  }

  const json = (await res.json()) as { hits?: { hits?: unknown[] } };
  const hits = json?.hits?.hits ?? [];

  let ingested = 0;
  for (const hit of hits) {
    const event = normalizeWazuh(hit);
    if (!event) {
      console.warn("[wazuh] dropped malformed hit");
      continue;
    }
    await queue.enqueue("wazuh", event);
    ingested++;
  }

  if (ingested > 0) {
    console.log(`[wazuh] ingested ${ingested} events since ${since}`);
  }

  lastSeen = now;
}

export function startWazuhConnector(): void {
  console.log(`[wazuh] polling ${WAZUH_URL}/${WAZUH_INDEX} every ${WAZUH_POLL_MS}ms`);
  poll().catch(console.error);
  setInterval(() => poll().catch(console.error), WAZUH_POLL_MS);
}
