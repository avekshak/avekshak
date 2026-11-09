import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { NormalizedEventSchema, VerdictSchema } from "./index.js";

const validEvent = {
  id: randomUUID(),
  ts: new Date().toISOString(),
  source: "syslog" as const,
  category: "authentication",
  action: "login_failed",
  outcome: "failure" as const,
  severity: 40,
  actor: { user: "root", ip: "203.0.113.10" },
  target: { host: "db-prod-01" },
  raw: { msg: "Failed password for root" },
};

describe("NormalizedEventSchema", () => {
  it("accepts a well-formed event", () => {
    const parsed = NormalizedEventSchema.safeParse(validEvent);
    expect(parsed.success).toBe(true);
  });

  it("rejects an event with a bad source", () => {
    const parsed = NormalizedEventSchema.safeParse({
      ...validEvent,
      source: "crowdstrike",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects an event with out-of-range severity", () => {
    const parsed = NormalizedEventSchema.safeParse({
      ...validEvent,
      severity: 500,
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects an event missing required fields", () => {
    const parsed = NormalizedEventSchema.safeParse({ id: validEvent.id });
    expect(parsed.success).toBe(false);
  });
});

describe("VerdictSchema", () => {
  it("accepts a valid verdict", () => {
    const parsed = VerdictSchema.safeParse({
      verdict: "critical",
      confidence: 94,
      rationale: "Large outbound transfer to unknown foreign IP at 2am",
      recommendedAction: "Block the destination IP",
    });
    expect(parsed.success).toBe(true);
  });

  it("rejects an unknown verdict label", () => {
    const parsed = VerdictSchema.safeParse({
      verdict: "maybe",
      confidence: 50,
      rationale: "x",
      recommendedAction: "y",
    });
    expect(parsed.success).toBe(false);
  });
});
