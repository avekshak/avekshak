import { describe, it, expect } from "vitest";
import { correlationKey, shouldCorrelate, CORRELATION_WINDOW_MS } from "../src/correlate.js";
import type { AlertSummary } from "../src/correlate.js";

function alert(overrides: Partial<AlertSummary> = {}): AlertSummary {
  return {
    id: crypto.randomUUID(),
    ts: new Date("2026-11-10T10:00:00Z"),
    severity: 40,
    actorIp: null,
    actorUser: null,
    targetHost: null,
    title: "Test Alert",
    ...overrides,
  };
}

// ── correlationKey ────────────────────────────────────────────────────────────

describe("correlationKey", () => {
  it("returns ip key when actorIp is set", () => {
    expect(correlationKey(alert({ actorIp: "1.2.3.4" }))).toBe("ip:1.2.3.4");
  });

  it("prefers actorIp over actorUser", () => {
    expect(correlationKey(alert({ actorIp: "1.2.3.4", actorUser: "admin" }))).toBe("ip:1.2.3.4");
  });

  it("falls back to actorUser when no actorIp", () => {
    expect(correlationKey(alert({ actorUser: "admin" }))).toBe("user:admin");
  });

  it("falls back to targetHost when no ip or user", () => {
    expect(correlationKey(alert({ targetHost: "web-01" }))).toBe("host:web-01");
  });

  it("returns null when no groupable field", () => {
    expect(correlationKey(alert())).toBeNull();
  });
});

// ── shouldCorrelate ───────────────────────────────────────────────────────────

describe("shouldCorrelate", () => {
  it("correlates two alerts with same IP within the window", () => {
    const a = alert({ actorIp: "10.0.0.1", ts: new Date("2026-11-10T10:00:00Z") });
    const b = alert({ actorIp: "10.0.0.1", ts: new Date("2026-11-10T10:05:00Z") });
    expect(shouldCorrelate(a, b)).toBe(true);
  });

  it("does not correlate alerts with different IPs", () => {
    const a = alert({ actorIp: "10.0.0.1" });
    const b = alert({ actorIp: "10.0.0.2" });
    expect(shouldCorrelate(a, b)).toBe(false);
  });

  it("does not correlate alerts outside the time window", () => {
    const base = new Date("2026-11-10T10:00:00Z");
    const outside = new Date(base.getTime() + CORRELATION_WINDOW_MS + 1);
    const a = alert({ actorIp: "10.0.0.1", ts: base });
    const b = alert({ actorIp: "10.0.0.1", ts: outside });
    expect(shouldCorrelate(a, b)).toBe(false);
  });

  it("correlates alerts exactly at the window boundary", () => {
    const base = new Date("2026-11-10T10:00:00Z");
    const boundary = new Date(base.getTime() + CORRELATION_WINDOW_MS);
    const a = alert({ actorIp: "10.0.0.1", ts: base });
    const b = alert({ actorIp: "10.0.0.1", ts: boundary });
    expect(shouldCorrelate(a, b)).toBe(true);
  });

  it("correlates alerts sharing actorUser", () => {
    const a = alert({ actorUser: "attacker", ts: new Date("2026-11-10T10:00:00Z") });
    const b = alert({ actorUser: "attacker", ts: new Date("2026-11-10T10:10:00Z") });
    expect(shouldCorrelate(a, b)).toBe(true);
  });

  it("does not correlate when one alert has no groupable field", () => {
    const a = alert({ actorIp: "10.0.0.1" });
    const b = alert();
    expect(shouldCorrelate(a, b)).toBe(false);
  });

  it("does not correlate when keys are different types (ip vs user)", () => {
    const a = alert({ actorIp: "10.0.0.1" });
    const b = alert({ actorUser: "admin" });
    expect(shouldCorrelate(a, b)).toBe(false);
  });
});
