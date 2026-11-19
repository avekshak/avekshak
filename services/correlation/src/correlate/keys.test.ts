import { describe, it, expect } from "vitest";
import type { Alert } from "@avekshak/schema";
import {
  correlationKey,
  alertsCorrelate,
  withinWindow,
  CORRELATION_WINDOW_MS,
} from "./keys.js";

function alert(over: Partial<Alert> = {}): Alert {
  return {
    id: "00000000-0000-4000-8000-000000000001",
    eventId: "00000000-0000-4000-8000-000000000002",
    ruleId: "auth-failed-login",
    title: "Failed authentication",
    severity: 40,
    ts: "2026-06-01T02:00:00.000Z",
    actorIp: "203.0.113.9",
    actorUser: "root",
    targetHost: "db-prod-1",
    ...over,
  };
}

describe("correlationKey", () => {
  it("prefers actor.ip", () => {
    expect(correlationKey(alert())).toBe("ip:203.0.113.9");
  });
  it("falls back to actor.user when no ip", () => {
    expect(correlationKey(alert({ actorIp: undefined }))).toBe("user:root");
  });
  it("falls back to target.host when no ip/user", () => {
    expect(
      correlationKey(alert({ actorIp: undefined, actorUser: undefined })),
    ).toBe("host:db-prod-1");
  });
  it("returns null when no correlatable identity", () => {
    expect(
      correlationKey(
        alert({ actorIp: undefined, actorUser: undefined, targetHost: undefined }),
      ),
    ).toBeNull();
  });
});

describe("alertsCorrelate", () => {
  it("correlates two alerts sharing an IP within the window", () => {
    const a = alert({ ts: "2026-06-01T02:00:00.000Z" });
    const b = alert({ ts: "2026-06-01T02:10:00.000Z" });
    expect(alertsCorrelate(a, b)).toBe(true);
  });

  it("does NOT correlate different IPs even if close in time", () => {
    const a = alert({ actorIp: "1.1.1.1" });
    const b = alert({ actorIp: "2.2.2.2" });
    expect(alertsCorrelate(a, b)).toBe(false);
  });

  it("does NOT correlate same IP outside the window", () => {
    const a = alert({ ts: "2026-06-01T02:00:00.000Z" });
    const b = alert({
      ts: new Date(Date.parse("2026-06-01T02:00:00.000Z") + CORRELATION_WINDOW_MS + 1000).toISOString(),
    });
    expect(alertsCorrelate(a, b)).toBe(false);
  });

  it("correlates exactly at the window boundary", () => {
    const a = alert({ ts: "2026-06-01T02:00:00.000Z" });
    const b = alert({
      ts: new Date(Date.parse("2026-06-01T02:00:00.000Z") + CORRELATION_WINDOW_MS).toISOString(),
    });
    expect(alertsCorrelate(a, b)).toBe(true); // <= is inclusive
  });

  it("does NOT correlate when either key is null", () => {
    const a = alert();
    const b = alert({ actorIp: undefined, actorUser: undefined, targetHost: undefined });
    expect(alertsCorrelate(a, b)).toBe(false);
  });

  it("correlates by user when neither has an IP", () => {
    const a = alert({ actorIp: undefined, actorUser: "alice" });
    const b = alert({ actorIp: undefined, actorUser: "alice", targetHost: "other" });
    expect(alertsCorrelate(a, b)).toBe(true);
  });
});

describe("withinWindow", () => {
  it("is true inside the window", () => {
    expect(
      withinWindow("2026-06-01T02:10:00.000Z", "2026-06-01T02:00:00.000Z"),
    ).toBe(true);
  });
  it("is false past the window", () => {
    expect(
      withinWindow("2026-06-01T03:00:00.000Z", "2026-06-01T02:00:00.000Z"),
    ).toBe(false);
  });
  it("is inclusive at the boundary", () => {
    const latest = "2026-06-01T02:00:00.000Z";
    const edge = new Date(Date.parse(latest) + CORRELATION_WINDOW_MS).toISOString();
    expect(withinWindow(edge, latest)).toBe(true);
  });
});
