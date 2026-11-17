import { Redis } from "ioredis";
import type { NormalizedEvent, Rule } from "@avekshak/schema";
import { resolveField } from "../rules/evaluator.js";

const REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";

/**
 * Redis-backed sliding-bucket counter for windowed rules. For each candidate
 * event we INCR a key scoped to (ruleId, groupBy value, time bucket) with a
 * TTL equal to the window. The rule "fires" exactly once — on the event that
 * pushes the count to the threshold — so N events over the threshold still
 * yield a single alert for that bucket.
 */
export class WindowCounter {
  private redis: Redis;

  constructor(redis?: Redis) {
    this.redis = redis ?? new Redis(REDIS_URL, { maxRetriesPerRequest: null });
  }

  /** Bucket an event's timestamp into window-sized slots. */
  private bucket(ev: NormalizedEvent, seconds: number): number {
    return Math.floor(Date.parse(ev.ts) / (seconds * 1000));
  }

  private key(ruleId: string, groupVal: string, bucket: number): string {
    return `win:${ruleId}:${groupVal}:${bucket}`;
  }

  /**
   * Record one matching event against a windowed rule and report whether this
   * event is the one that trips the threshold. Returns false when the rule has
   * no window, when the groupBy field is absent, or when the count is below (or
   * already past) the threshold.
   */
  async record(ev: NormalizedEvent, rule: Rule): Promise<boolean> {
    if (!rule.window) return false;
    const groupVal = resolveField(ev, rule.window.groupBy);
    if (groupVal === undefined || groupVal === null) return false;

    const bucket = this.bucket(ev, rule.window.seconds);
    const key = this.key(rule.id, String(groupVal), bucket);

    const count = await this.redis.incr(key);
    if (count === 1) {
      // First hit in this bucket — set the TTL so the window expires.
      await this.redis.expire(key, rule.window.seconds);
    }
    // Fire exactly on the threshold-crossing event.
    return count === rule.window.threshold;
  }

  async close(): Promise<void> {
    await this.redis.quit();
  }
}
