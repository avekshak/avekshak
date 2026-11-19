import { Queue, Worker, type Job, type Processor } from "bullmq";
import { Redis } from "ioredis";

/**
 * Thin typed wrapper over BullMQ. Keeps the producer/consumer surface small
 * and swappable — the rest of the system talks to enqueue()/createWorker()
 * and never touches BullMQ directly, so the backing bus (Redis today, Kafka
 * later) can change without touching business logic.
 */

const REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";

function connection(): Redis {
  // maxRetriesPerRequest must be null for BullMQ blocking commands.
  return new Redis(REDIS_URL, { maxRetriesPerRequest: null });
}

export interface TypedQueue<T> {
  enqueue(name: string, data: T): Promise<Job>;
  close(): Promise<void>;
}

export function createQueue<T>(queueName: string): TypedQueue<T> {
  const queue = new Queue<T>(queueName, { connection: connection() });
  return {
    enqueue: (name, data) => (queue as Queue).add(name, data) as Promise<Job>,
    close: () => queue.close(),
  };
}

export function createWorker<T>(
  queueName: string,
  processor: Processor<T>,
): Worker<T> {
  return new Worker<T>(queueName, processor, { connection: connection() });
}

export type { Job };
