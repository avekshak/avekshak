import { describe, it, expect } from "vitest";
import type { IncidentContext } from "../llm/provider.js";
import { evidenceTextFor, scoreGroundedness } from "./groundedness.js";

describe("scoreGroundedness", () => {
  it("scores 1.0 when the rationale cites no concrete indicators", () => {
    const r = scoreGroundedness("This looks like routine backup activity.", "any evidence");
    expect(r.score).toBe(1);
    expect(r.hallucinated).toEqual([]);
  });

  it("scores 1.0 when a cited IP is present in the evidence", () => {
    const r = scoreGroundedness(
      "Traffic from 203.0.113.50 to the finance bucket.",
      "actor ip 203.0.113.50 reading s3://corp-financials-prod",
    );
    expect(r.score).toBe(1);
    expect(r.grounded).toContain("203.0.113.50");
    expect(r.hallucinated).toEqual([]);
  });

  it("flags an IP absent from the evidence as hallucinated", () => {
    const r = scoreGroundedness(
      "Command-and-control to 6.6.6.6 observed.",
      "actor ip 203.0.113.50 only",
    );
    expect(r.hallucinated).toContain("6.6.6.6");
    expect(r.score).toBeLessThan(1);
  });

  it("flags a fabricated hash", () => {
    const fakeHash = "a".repeat(64);
    const r = scoreGroundedness(
      `Dropped a payload with sha256 ${fakeHash}.`,
      "no hashes in this incident",
    );
    expect(r.hallucinated).toContain(fakeHash);
    expect(r.score).toBe(0);
  });

  it("computes a partial score when some indicators are grounded", () => {
    const r = scoreGroundedness(
      "Saw 203.0.113.50 and also 6.6.6.6.",
      "evidence mentions 203.0.113.50",
    );
    expect(r.grounded).toContain("203.0.113.50");
    expect(r.hallucinated).toContain("6.6.6.6");
    expect(r.score).toBe(0.5);
  });

  it("detects a CVE citation", () => {
    const r = scoreGroundedness("Exploits CVE-2021-44228.", "nothing about log4j here");
    expect(r.hallucinated).toContain("cve-2021-44228");
  });
});

describe("evidenceTextFor", () => {
  const ctx: IncidentContext = {
    incidentId: "e0000000-0000-0000-0000-000000000000",
    title: "Activity from a known-bad IP",
    severity: 85,
    correlationKey: "ip:203.0.113.50",
    createdAt: "2026-06-01T02:00:00.000Z",
    alerts: [
      {
        id: "a1",
        eventId: "v1",
        ruleId: "known-bad-ip",
        title: "Activity from a known-bad IP",
        severity: 85,
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
        raw: { secret: "should-not-leak" },
      },
    ],
  };

  it("contains the fields the model is shown and omits the raw blob", () => {
    const evidence = evidenceTextFor(ctx);
    expect(evidence).toContain("203.0.113.50");
    expect(evidence).toContain("known-bad-ip");
    // The dropped raw blob must not count as evidence.
    expect(evidence).not.toContain("should-not-leak");
  });

  it("makes a genuinely-cited IP ground against the real incident", () => {
    const evidence = evidenceTextFor(ctx);
    const r = scoreGroundedness("Activity from 203.0.113.50.", evidence);
    expect(r.score).toBe(1);
  });
});
