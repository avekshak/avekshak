import { describe, it, expect } from "vitest";
import type { IncidentContext } from "../llm/provider.js";
import { scoreTriage } from "./scoreTriage.js";

/** Exfil-shaped incident: high severity + a known-bad-ip title + an "Exfiltration" action. */
function exfilCtx(): IncidentContext {
  return {
    incidentId: "e0000000-0000-0000-0000-000000000000",
    title: "Activity from a known-bad IP",
    severity: 85,
    correlationKey: "ip:203.0.113.50",
    createdAt: "2026-06-01T02:00:00.000Z",
    alerts: [
      {
        id: "a1",
        eventId: "v1",
        ruleId: "cloud-exfiltration-finding",
        title: "Cloud exfiltration finding",
        severity: 85,
        ts: "2026-06-01T02:00:00.000Z",
        actorIp: "203.0.113.50",
        actorUser: "svc-backup",
        targetHost: null,
      },
      {
        id: "a2",
        eventId: "v1",
        ruleId: "known-bad-ip",
        title: "Activity from a known-bad IP",
        severity: 75,
        ts: "2026-06-01T02:00:00.000Z",
        actorIp: "203.0.113.50",
        actorUser: "svc-backup",
        targetHost: null,
      },
    ],
    events: [
      {
        id: "v1",
        ts: "2026-06-01T02:00:00.000Z",
        source: "aws",
        category: "cloud",
        action: "Exfiltration:S3/ObjectRead.Unusual",
        outcome: "unknown",
        severity: 85,
        actor: { user: "svc-backup", ip: "203.0.113.50" },
        target: { resource: "s3://corp-financials-prod" },
        location: { country: "RU", city: "Moscow" },
        raw: {},
      },
    ],
  };
}

/** A lone owner root login: moderate severity, no malicious keyword, one host. */
function ownerLoginCtx(): IncidentContext {
  return {
    incidentId: "00000000-0000-0000-0000-00000000000a",
    title: "Successful root/admin login",
    severity: 60,
    correlationKey: "ip:198.51.100.200",
    createdAt: "2026-06-01T04:00:00.000Z",
    alerts: [
      {
        id: "b1",
        eventId: "w1",
        ruleId: "auth-root-login-success",
        title: "Successful root/admin login",
        severity: 60,
        ts: "2026-06-01T04:00:00.000Z",
        actorIp: "198.51.100.200",
        actorUser: "root",
        targetHost: "db-prod-1",
      },
    ],
    events: [
      {
        id: "w1",
        ts: "2026-06-01T04:00:00.000Z",
        source: "syslog",
        category: "authentication",
        action: "login_success",
        outcome: "success",
        severity: 20,
        actor: { user: "root", ip: "198.51.100.200" },
        target: { host: "db-prod-1" },
        location: { country: "US", city: "Honolulu" },
        raw: {},
      },
    ],
  };
}

/** No alerts, no events, floor severity — the empty / no-signal case. */
function emptyCtx(): IncidentContext {
  return {
    incidentId: "00000000-0000-0000-0000-00000000000e",
    title: "",
    severity: 0,
    correlationKey: "ip:0.0.0.0",
    createdAt: "2026-06-01T00:00:00.000Z",
    alerts: [],
    events: [],
  };
}

describe("scoreTriage", () => {
  it("scores the exfil incident critical", () => {
    const score = scoreTriage(exfilCtx());
    expect(score.verdict).toBe("critical");
    expect(score.confidence).toBeGreaterThanOrEqual(60);
    expect(score.basis.join(" ")).toMatch(/critical-severity keyword/);
  });

  it("does NOT score the lone owner login critical", () => {
    const score = scoreTriage(ownerLoginCtx());
    expect(score.verdict).not.toBe("critical");
    // suspicious or benign — both acceptable for a lone login with no malicious signal.
    expect(["suspicious", "benign"]).toContain(score.verdict);
  });

  it("scores an empty incident benign at the floor", () => {
    const score = scoreTriage(emptyCtx());
    expect(score.verdict).toBe("benign");
    expect(score.confidence).toBe(5); // CONF_FLOOR × 100
    expect(score.basis).toContain("no salient signals — defaulting to floor confidence");
  });

  it("is pure / deterministic (same input → same output)", () => {
    const ctx = exfilCtx();
    expect(scoreTriage(ctx)).toEqual(scoreTriage(ctx));
  });

  it("never exceeds the confidence ceiling", () => {
    const score = scoreTriage(exfilCtx());
    expect(score.confidence).toBeLessThanOrEqual(95);
  });
});
