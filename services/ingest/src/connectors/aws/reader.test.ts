import { describe, it, expect } from "vitest";
import type { TypedQueue } from "@avekshak/queue";
import type { NormalizedEvent } from "@avekshak/schema";
import { extractAwsRecords, processAwsRecords } from "./reader.js";

/** A queue stub that records what was enqueued. */
function fakeQueue(): {
  queue: TypedQueue<NormalizedEvent>;
  enqueued: Array<{ name: string; ev: NormalizedEvent }>;
} {
  const enqueued: Array<{ name: string; ev: NormalizedEvent }> = [];
  const queue = {
    async enqueue(name: string, ev: NormalizedEvent) {
      enqueued.push({ name, ev });
    },
    async close() {},
  } as unknown as TypedQueue<NormalizedEvent>;
  return { queue, enqueued };
}

describe("extractAwsRecords", () => {
  it("returns a JSON array as-is", () => {
    expect(extractAwsRecords([{ a: 1 }, { b: 2 }])).toEqual([
      { a: 1 },
      { b: 2 },
    ]);
  });

  it("unwraps a CloudTrail { Records: [...] } envelope", () => {
    const env = { Records: [{ eventID: "x" }, { eventID: "y" }] };
    expect(extractAwsRecords(env)).toEqual([
      { eventID: "x" },
      { eventID: "y" },
    ]);
  });

  it("wraps a single object in an array", () => {
    const one = { eventName: "ConsoleLogin" };
    expect(extractAwsRecords(one)).toEqual([one]);
  });

  it("returns [] for non-object input", () => {
    expect(extractAwsRecords(null)).toEqual([]);
    expect(extractAwsRecords(42)).toEqual([]);
    expect(extractAwsRecords("str")).toEqual([]);
  });
});

describe("processAwsRecords", () => {
  it("normalizes and enqueues a CloudTrail record", async () => {
    const { queue, enqueued } = fakeQueue();
    const rec = {
      eventID: "ct-1",
      eventTime: "2026-06-01T04:00:00Z",
      eventName: "ConsoleLogin",
      eventSource: "signin.amazonaws.com",
      sourceIPAddress: "203.0.113.50",
      awsRegion: "us-east-1",
      userIdentity: { type: "IAMUser", userName: "owner" },
    };
    const result = await processAwsRecords([rec], queue);
    expect(result).toEqual({ enqueued: 1, skipped: 0 });
    expect(enqueued).toHaveLength(1);
    expect(enqueued[0].name).toBe("aws");
    expect(enqueued[0].ev.source).toBe("aws");
    expect(enqueued[0].ev.action).toBe("ConsoleLogin");
    expect(enqueued[0].ev.actor.user).toBe("owner");
  });

  it("normalizes and enqueues a GuardDuty finding", async () => {
    const { queue, enqueued } = fakeQueue();
    const rec = {
      id: "gd-1",
      type: "UnauthorizedAccess:S3/MaliciousIPCaller.Custom",
      severity: 8,
      region: "us-east-1",
      resource: { resourceType: "S3Bucket" },
      createdAt: "2026-06-01T02:00:00.000Z",
      updatedAt: "2026-06-01T02:05:00.000Z",
    };
    const result = await processAwsRecords([rec], queue);
    expect(result).toEqual({ enqueued: 1, skipped: 0 });
    expect(enqueued[0].ev.action).toBe(
      "UnauthorizedAccess:S3/MaliciousIPCaller.Custom",
    );
    expect(enqueued[0].ev.severity).toBe(80);
    expect(enqueued[0].ev.outcome).toBe("unknown");
  });

  it("skips unrecognized records and reports the index", async () => {
    const { queue, enqueued } = fakeQueue();
    const skips: number[] = [];
    const records: unknown[] = [
      { eventName: "GetObject", eventTime: "2026-06-01T04:00:00Z" },
      null,
      { nonsense: true },
    ];
    const result = await processAwsRecords(records, queue, (i) =>
      skips.push(i),
    );
    expect(result).toEqual({ enqueued: 1, skipped: 2 });
    expect(skips).toEqual([1, 2]);
    expect(enqueued).toHaveLength(1);
  });

  it("derives a deterministic id from the record stable key", async () => {
    const rec = {
      eventID: "ct-dedupe",
      eventTime: "2026-06-01T04:00:00Z",
      eventName: "ConsoleLogin",
      eventSource: "signin.amazonaws.com",
    };
    const a = fakeQueue();
    const b = fakeQueue();
    await processAwsRecords([rec], a.queue);
    await processAwsRecords([rec], b.queue);
    // Same stable key → same event id across independent runs (dedupe no-op).
    expect(a.enqueued[0].ev.id).toBe(b.enqueued[0].ev.id);
  });
});
