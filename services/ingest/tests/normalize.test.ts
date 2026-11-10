import { describe, it, expect } from "vitest";
import { normalizeSyslog } from "../src/normalize/syslog.js";
import { normalizeWazuh } from "../src/normalize/wazuh.js";
import { normalizeCloudTrail, normalizeGuardDuty } from "../src/normalize/aws.js";

// ── Syslog ────────────────────────────────────────────────────────────────────

describe("normalizeSyslog", () => {
  it("parses a failed SSH login", () => {
    const line = "<34>Nov 10 02:00:00 web-01 sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2";
    const e = normalizeSyslog(line);
    expect(e).not.toBeNull();
    expect(e!.source).toBe("syslog");
    expect(e!.action).toBe("login_failed");
    expect(e!.outcome).toBe("failure");
    expect(e!.category).toBe("authentication");
    expect(e!.severity).toBeGreaterThan(0);
    expect(e!.id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("parses a successful SSH login", () => {
    const line = "<38>Nov 10 02:01:00 web-01 sshd[5678]: Accepted password for kunal from 10.0.0.1 port 22 ssh2";
    const e = normalizeSyslog(line);
    expect(e!.action).toBe("login_success");
    expect(e!.outcome).toBe("success");
    expect(e!.actor.user).toBe("kunal");
  });

  it("returns null for malformed input", () => {
    expect(normalizeSyslog("not a syslog line")).toBeNull();
    expect(normalizeSyslog(null)).toBeNull();
    expect(normalizeSyslog(42)).toBeNull();
  });
});

// ── Wazuh ─────────────────────────────────────────────────────────────────────

describe("normalizeWazuh", () => {
  it("parses a failed authentication hit", () => {
    const hit = {
      _source: {
        timestamp: "2026-11-10T02:00:00.000Z",
        agent: { name: "web-01", ip: "10.0.0.5" },
        rule: { description: "SSH login failed", level: 10, groups: ["authentication_failed", "pam"] },
        data: { srcip: "1.2.3.4", srcuser: "admin" },
        full_log: "Failed password for admin",
      },
    };
    const e = normalizeWazuh(hit);
    expect(e).not.toBeNull();
    expect(e!.source).toBe("wazuh");
    expect(e!.action).toBe("login_failed");
    expect(e!.outcome).toBe("failure");
    expect(e!.actor.ip).toBe("1.2.3.4");
    expect(e!.actor.user).toBe("admin");
    expect(e!.severity).toBeGreaterThan(50);
  });

  it("returns null for empty input", () => {
    expect(normalizeWazuh(null)).toBeNull();
    expect(normalizeWazuh({})).toBeNull();
    expect(normalizeWazuh({ _source: null })).toBeNull();
  });
});

// ── AWS CloudTrail ─────────────────────────────────────────────────────────────

describe("normalizeCloudTrail", () => {
  it("parses a successful API call", () => {
    const record = {
      eventTime: "2026-11-10T02:00:00Z",
      eventSource: "s3.amazonaws.com",
      eventName: "GetObject",
      sourceIPAddress: "203.0.113.1",
      userIdentity: { type: "IAMUser", userName: "kunal" },
    };
    const e = normalizeCloudTrail(record);
    expect(e).not.toBeNull();
    expect(e!.source).toBe("aws");
    expect(e!.outcome).toBe("success");
    expect(e!.action).toBe("get_object");
    expect(e!.actor.user).toBe("kunal");
    expect(e!.category).toBe("data_access");
  });

  it("marks error calls as failure with higher severity", () => {
    const record = {
      eventTime: "2026-11-10T02:00:00Z",
      eventSource: "iam.amazonaws.com",
      eventName: "AssumeRole",
      errorCode: "AccessDenied",
      errorMessage: "User is not authorized",
      sourceIPAddress: "203.0.113.5",
      userIdentity: { type: "IAMUser", userName: "attacker" },
    };
    const e = normalizeCloudTrail(record);
    expect(e!.outcome).toBe("failure");
    expect(e!.severity).toBeGreaterThanOrEqual(70);
  });

  it("returns null for missing eventName", () => {
    expect(normalizeCloudTrail({})).toBeNull();
    expect(normalizeCloudTrail(null)).toBeNull();
  });
});

// ── AWS GuardDuty ─────────────────────────────────────────────────────────────

describe("normalizeGuardDuty", () => {
  it("parses an exfiltration finding", () => {
    const finding = {
      CreatedAt: "2026-11-10T02:00:00Z",
      Type: "Exfiltration:S3/ObjectRead.Unusual",
      Severity: 8,
      Title: "Unusual S3 object read",
      Resource: { ResourceType: "S3Bucket", AccessKeyDetails: { UserName: "svc-account" } },
      Service: {
        Action: {
          ActionType: "AWS_API_CALL",
          AwsApiCallAction: { CallerType: "Remote", RemoteIpDetails: { IpAddressV4: "5.6.7.8" } },
        },
      },
    };
    const e = normalizeGuardDuty(finding);
    expect(e).not.toBeNull();
    expect(e!.source).toBe("aws");
    expect(e!.category).toBe("data_access");
    expect(e!.severity).toBe(80);
    expect(e!.actor.ip).toBe("5.6.7.8");
    expect(e!.actor.user).toBe("svc-account");
  });

  it("returns null for missing Type", () => {
    expect(normalizeGuardDuty({})).toBeNull();
    expect(normalizeGuardDuty(null)).toBeNull();
  });
});
