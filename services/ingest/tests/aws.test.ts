import { describe, it, expect } from "vitest";
import { normalizeCloudTrail, normalizeGuardDuty } from "../src/normalize/aws.js";
import { readFileSync } from "fs";
import { join } from "path";

const ctFixture = JSON.parse(
  readFileSync(join(import.meta.dirname, "../fixtures/aws/cloudtrail-sample.json"), "utf8"),
) as { Records: unknown[] };

const gdFixture = JSON.parse(
  readFileSync(join(import.meta.dirname, "../fixtures/aws/guardduty-sample.json"), "utf8"),
) as { Findings: unknown[] };

describe("AWS CloudTrail connector", () => {
  it("normalizes all 3 fixture records", () => {
    const events = ctFixture.Records.map(normalizeCloudTrail).filter(Boolean);
    expect(events).toHaveLength(3);
  });

  it("marks GetObject as success, data_access category", () => {
    const e = normalizeCloudTrail(ctFixture.Records[0]);
    expect(e!.outcome).toBe("success");
    expect(e!.category).toBe("data_access");
    expect(e!.action).toBe("get_object");
    expect(e!.actor.user).toBe("kunal");
    expect(e!.source).toBe("aws");
  });

  it("marks AssumeRole with errorCode as failure with elevated severity", () => {
    const e = normalizeCloudTrail(ctFixture.Records[1]);
    expect(e!.outcome).toBe("failure");
    expect(e!.severity).toBeGreaterThanOrEqual(70);
    expect(e!.actor.user).toBe("attacker");
  });

  it("marks TerminateInstances as success with elevated severity", () => {
    const e = normalizeCloudTrail(ctFixture.Records[2]);
    expect(e!.outcome).toBe("success");
    expect(e!.severity).toBeGreaterThanOrEqual(50);
  });

  it("returns null for missing eventName", () => {
    expect(normalizeCloudTrail({})).toBeNull();
    expect(normalizeCloudTrail(null)).toBeNull();
  });
});

describe("AWS GuardDuty connector", () => {
  it("normalizes both fixture findings", () => {
    const events = gdFixture.Findings.map(normalizeGuardDuty).filter(Boolean);
    expect(events).toHaveLength(2);
  });

  it("parses exfiltration finding correctly", () => {
    const e = normalizeGuardDuty(gdFixture.Findings[0]);
    expect(e!.source).toBe("aws");
    expect(e!.category).toBe("data_access");
    expect(e!.severity).toBe(80);
    expect(e!.actor.ip).toBe("5.6.7.8");
    expect(e!.actor.user).toBe("svc-account");
  });

  it("parses unauthorized access finding correctly", () => {
    const e = normalizeGuardDuty(gdFixture.Findings[1]);
    expect(e!.severity).toBe(50);
    expect(e!.actor.ip).toBe("91.108.4.1");
    expect(e!.actor.user).toBe("admin");
  });

  it("returns null for missing Type", () => {
    expect(normalizeGuardDuty({})).toBeNull();
    expect(normalizeGuardDuty(null)).toBeNull();
  });
});
