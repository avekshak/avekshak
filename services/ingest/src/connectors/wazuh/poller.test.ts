import { describe, it, expect } from "vitest";
import type { TypedQueue } from "@avekshak/queue";
import type { NormalizedEvent } from "@avekshak/schema";
import { processWazuhResponse, type EsSearchResponse } from "./poller.js";

function fakeQueue() {
  const enqueued: NormalizedEvent[] = [];
  const queue: TypedQueue<NormalizedEvent> = {
    enqueue: async (_name, data) => {
      enqueued.push(data);
      return { data } as never;
    },
    close: async () => {},
  };
  return { queue, enqueued };
}

const validHit = {
  _id: "alert-1",
  _source: {
    timestamp: "2026-06-01T12:00:00.000Z",
    rule: { level: 10, groups: ["authentication_failed"] },
    agent: { name: "db-prod-1", ip: "10.0.0.20" },
    data: { srcip: "203.0.113.9", srcuser: "root" },
  },
};

const malformedHit = { _id: "alert-bad", _source: { timestamp: "not-a-date" } };

describe("processWazuhResponse", () => {
  it("enqueues valid hits and skips malformed ones", async () => {
    const { queue, enqueued } = fakeQueue();
    const res: EsSearchResponse = { hits: { hits: [validHit, malformedHit] } };
    const result = await processWazuhResponse(res, queue);
    expect(result.enqueued).toBe(1);
    expect(result.skipped).toBe(1);
    expect(enqueued).toHaveLength(1);
    expect(enqueued[0].source).toBe("wazuh");
    expect(enqueued[0].actor.ip).toBe("203.0.113.9");
  });

  it("derives a deterministic event id from the doc _id (dedupe foundation)", async () => {
    const res: EsSearchResponse = { hits: { hits: [validHit] } };

    const a = fakeQueue();
    await processWazuhResponse(res, a.queue);
    const b = fakeQueue();
    await processWazuhResponse(res, b.queue);

    expect(a.enqueued[0].id).toBe(b.enqueued[0].id);
  });

  it("handles an empty response", async () => {
    const { queue, enqueued } = fakeQueue();
    const result = await processWazuhResponse({}, queue);
    expect(result).toEqual({ enqueued: 0, skipped: 0 });
    expect(enqueued).toHaveLength(0);
  });
});
