import { describe, it, expect } from "vitest";
import { NormalizedEventSchema } from "@avekshak/schema";
import { normalizeSyslog } from "./normalize/syslog.js";
import { normalizeWazuh } from "./normalize/wazuh.js";
import { normalizeAws } from "./normalize/aws.js";

describe("normalizeSyslog", () => {
  it("parses a failed ssh login with PRI, user and ip", () => {
    const line =
      "<38>Jun  1 12:00:00 webhost sshd[1234]: Failed password for root from 203.0.113.9 port 2222 ssh2";
    const ev = normalizeSyslog(line);
    expect(ev).not.toBeNull();
    expect(NormalizedEventSchema.safeParse(ev).success).toBe(true);
    expect(ev!.source).toBe("syslog");
    expect(ev!.category).toBe("authentication");
    expect(ev!.action).toBe("login_failed");
    expect(ev!.outcome).toBe("failure");
    expect(ev!.actor.user).toBe("root");
    expect(ev!.actor.ip).toBe("203.0.113.9");
    expect(ev!.severity).toBeGreaterThanOrEqual(50);
  });

  it("parses an accepted ssh login as success", () => {
    const line =
      "<86>Jun  1 12:05:00 webhost sshd[1250]: Accepted password for alice from 10.0.0.5 port 51000 ssh2";
    const ev = normalizeSyslog(line)!;
    expect(ev.action).toBe("login_success");
    expect(ev.outcome).toBe("success");
    expect(ev.actor.user).toBe("alice");
  });

  it("falls back to a generic system event for unrecognized lines", () => {
    const ev = normalizeSyslog("<13>something totally unstructured happened")!;
    expect(ev.source).toBe("syslog");
    expect(ev.category).toBe("system");
    expect(ev.outcome).toBe("unknown");
  });

  it.each([["", "empty"], ["   ", "whitespace"]])(
    "returns null for %s input (%s)",
    (input) => {
      expect(normalizeSyslog(input)).toBeNull();
    },
  );

  it("returns null for non-string input", () => {
    // @ts-expect-error intentional misuse
    expect(normalizeSyslog(42)).toBeNull();
  });
});

describe("normalizeWazuh", () => {
  const authFail = {
    timestamp: "2026-06-01T12:00:00.000Z",
    rule: { level: 10, description: "sshd: authentication failed", groups: ["authentication_failed"] },
    agent: { name: "db-prod-1", ip: "10.0.0.20" },
    data: { srcip: "203.0.113.9", srcuser: "root" },
  };

  it("normalizes a Wazuh auth-failure doc", () => {
    const ev = normalizeWazuh(authFail)!;
    expect(NormalizedEventSchema.safeParse(ev).success).toBe(true);
    expect(ev.source).toBe("wazuh");
    expect(ev.category).toBe("authentication");
    expect(ev.action).toBe("login_failed");
    expect(ev.outcome).toBe("failure");
    expect(ev.actor.ip).toBe("203.0.113.9");
    expect(ev.actor.user).toBe("root");
    expect(ev.target.host).toBe("db-prod-1");
    expect(ev.severity).toBe(Math.round((10 / 15) * 100));
  });

  it("keeps the original doc under raw", () => {
    const ev = normalizeWazuh(authFail)!;
    expect(ev.raw).toMatchObject({ rule: { level: 10 } });
  });

  it.each([
    [null, "null"],
    [undefined, "undefined"],
    [[], "array"],
    ["a string", "string"],
    [123, "number"],
  ])("returns null for %s input (%s)", (input) => {
    expect(normalizeWazuh(input)).toBeNull();
  });

  it("returns null when timestamp is unparseable", () => {
    expect(normalizeWazuh({ timestamp: "not-a-date", rule: { level: 5 } })).toBeNull();
  });
});

describe("normalizeAws", () => {
  const cloudTrail = {
    eventTime: "2026-06-01T04:00:00Z",
    eventName: "ConsoleLogin",
    eventSource: "signin.amazonaws.com",
    sourceIPAddress: "198.51.100.7",
    awsRegion: "us-east-1",
    userIdentity: { userName: "owner", type: "IAMUser" },
  };

  const guardDuty = {
    updatedAt: "2026-06-01T02:00:00Z",
    type: "UnauthorizedAccess:EC2/TorIPCaller",
    severity: 8,
    region: "us-east-1",
    service: { action: {} },
    resource: { resourceType: "Instance" },
  };

  it("normalizes a CloudTrail success event", () => {
    const ev = normalizeAws(cloudTrail)!;
    expect(NormalizedEventSchema.safeParse(ev).success).toBe(true);
    expect(ev.source).toBe("aws");
    expect(ev.category).toBe("cloud");
    expect(ev.action).toBe("ConsoleLogin");
    expect(ev.outcome).toBe("success");
    expect(ev.actor.user).toBe("owner");
    expect(ev.actor.ip).toBe("198.51.100.7");
    expect(ev.location?.city).toBe("us-east-1");
  });

  it("marks a CloudTrail event with errorCode as failure", () => {
    const ev = normalizeAws({ ...cloudTrail, errorCode: "AccessDenied" })!;
    expect(ev.outcome).toBe("failure");
    expect(ev.severity).toBe(50);
  });

  it("normalizes a GuardDuty finding and scales severity 0-10 → 0-100", () => {
    const ev = normalizeAws(guardDuty)!;
    expect(ev.source).toBe("aws");
    expect(ev.action).toBe("UnauthorizedAccess:EC2/TorIPCaller");
    expect(ev.severity).toBe(80);
    expect(ev.target.resource).toBe("Instance");
  });

  it.each([
    [null, "null"],
    [{}, "empty object (unrecognized)"],
    [{ foo: "bar" }, "unknown shape"],
    [[], "array"],
  ])("returns null for %s input (%s)", (input) => {
    expect(normalizeAws(input)).toBeNull();
  });
});
