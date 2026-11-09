import { describe, it, expect, afterAll } from "vitest";
import { createQueue, createWorker } from "./index.js";

interface Payload {
  value: number;
}

// Unique queue name per run to avoid cross-test interference.
const QUEUE = `test-queue-${Date.now()}`;

describe("queue wrapper (integration — requires Redis)", () => {
  const workers: Array<{ close: () => Promise<void> }> = [];
  const queues: Array<{ close: () => Promise<void> }> = [];

  afterAll(async () => {
    await Promise.all(workers.map((w) => w.close()));
    await Promise.all(queues.map((q) => q.close()));
  });

  it("delivers an enqueued job to a worker", async () => {
    const received = new Promise<Payload>((resolve) => {
      const worker = createWorker<Payload>(QUEUE, async (job) => {
        resolve(job.data);
      });
      workers.push(worker);
    });

    const queue = createQueue<Payload>(QUEUE);
    queues.push(queue);
    await queue.enqueue("job-1", { value: 42 });

    const data = await received;
    expect(data.value).toBe(42);
  }, 15000);
});
