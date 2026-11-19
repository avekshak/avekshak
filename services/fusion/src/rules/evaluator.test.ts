import { describe, it, expect, beforeAll } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { NormalizedEvent, Rule } from "@avekshak/schema";
import { loadRulesFromDir } from "./loader.js";
import {
  resolveField,
  matchesCondition,
  matchesRule,
  evaluate,
} from "./evaluator.js";

const DETECTIONS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../../detections",
);

function makeEvent(over: Partial<NormalizedEvent> = {}): NormalizedEvent {
  return {
    id: "00000000-0000-4000-8000-000000000000",
    ts: "2026-06-01T02:00:00.000Z",
    source: "syslog",
    category: "authentication",
    action: "login_failed",
    outcome: "failure",
    severity: 40,
    actor: { user: "root", ip: "203.0.113.9" },
    target: { host: "db-prod-1" },
    location: { country: "US", city: "us-east-1" },
    raw: {},
    ...over,
  };
}

describe("resolveField", () => {
  it("resolves nested dotted paths", () => {
    const ev = makeEvent();
    expect(resolveField(ev, "actor.ip")).toBe("203.0.113.9");
    expect(resolveField(ev, "outcome")).toBe("failure");
    expect(resolveField(ev, "location.country")).toBe("US");
  });
  it("returns undefined for missing paths", () => {
    const ev = makeEvent({ location: undefined });
    expect(resolveField(ev, "location.country")).toBeUndefined();
    expect(resolveField(ev, "nope.nope")).toBeUndefined();
  });
});

describe("matchesCondition", () => {
  const ev = makeEvent({ severity: 85 });
  it("eq / neq", () => {
    expect(matchesCondition(ev, { field: "outcome", op: "eq", value: "failure" })).toBe(true);
    expect(matchesCondition(ev, { field: "outcome", op: "neq", value: "success" })).toBe(true);
    expect(matchesCondition(ev, { field: "outcome", op: "eq", value: "success" })).toBe(false);
  });
  it("in", () => {
    expect(matchesCondition(ev, { field: "actor.user", op: "in", value: ["root", "admin"] })).toBe(true);
    expect(matchesCondition(ev, { field: "actor.user", op: "in", value: ["nobody"] })).toBe(false);
  });
  it("gte / lte", () => {
    expect(matchesCondition(ev, { field: "severity", op: "gte", value: 80 })).toBe(true);
    expect(matchesCondition(ev, { field: "severity", op: "lte", value: 80 })).toBe(false);
  });
  it("contains", () => {
    const g = makeEvent({ action: "Exfiltration:S3/ObjectRead.Unusual" });
    expect(matchesCondition(g, { field: "action", op: "contains", value: "Exfiltration" })).toBe(true);
    expect(matchesCondition(g, { field: "action", op: "contains", value: "Nope" })).toBe(false);
  });
  it("exists", () => {
    expect(matchesCondition(ev, { field: "actor.ip", op: "exists", value: true })).toBe(true);
    const noip = makeEvent({ actor: { user: "root" } });
    expect(matchesCondition(noip, { field: "actor.ip", op: "exists", value: true })).toBe(false);
    expect(matchesCondition(noip, { field: "actor.ip", op: "exists", value: false })).toBe(true);
  });
});

describe("matchesRule — disabled rules never match", () => {
  it("skips disabled rule", () => {
    const rule: Rule = {
      id: "x", title: "x", severity: 10, enabled: false,
      when: [{ field: "outcome", op: "eq", value: "failure" }],
    };
    expect(matchesRule(makeEvent(), rule)).toBe(false);
  });
});

describe("shipped detection rules (table-driven)", () => {
  let rules: Rule[];
  const byId = (id: string) => rules.find((r) => r.id === id)!;

  beforeAll(async () => {
    rules = await loadRulesFromDir(DETECTIONS_DIR);
  });

  it("loads all shipped rules", () => {
    expect(rules.length).toBeGreaterThanOrEqual(10);
  });

  const cases: Array<{
    rule: string;
    hit: Partial<NormalizedEvent>;
    miss: Partial<NormalizedEvent>;
  }> = [
    {
      rule: "auth-failed-login",
      hit: { category: "authentication", outcome: "failure" },
      miss: { category: "authentication", outcome: "success" },
    },
    {
      rule: "auth-root-login-success",
      hit: { category: "authentication", outcome: "success", actor: { user: "root" } },
      miss: { category: "authentication", outcome: "success", actor: { user: "alice" } },
    },
    {
      rule: "aws-console-login-root",
      hit: { source: "aws", action: "ConsoleLogin", actor: { user: "owner" } },
      miss: { source: "aws", action: "ConsoleLogin", actor: { user: "alice" } },
    },
    {
      rule: "aws-access-denied",
      hit: { source: "aws", outcome: "failure" },
      miss: { source: "aws", outcome: "success" },
    },
    {
      rule: "cloud-exfiltration-finding",
      hit: { source: "aws", action: "Exfiltration:S3/ObjectRead.Unusual" },
      miss: { source: "aws", action: "ConsoleLogin" },
    },
    {
      rule: "cloud-unauthorized-access",
      hit: { source: "aws", action: "UnauthorizedAccess:S3/MaliciousIPCaller.Custom" },
      miss: { source: "aws", action: "GetObject" },
    },
    {
      rule: "known-bad-ip",
      hit: { actor: { ip: "203.0.113.50" } },
      miss: { actor: { ip: "10.0.0.1" } },
    },
    {
      rule: "high-severity-source",
      hit: { severity: 90 },
      miss: { severity: 40 },
    },
    {
      rule: "file-integrity-change",
      hit: { category: "syscheck" },
      miss: { category: "authentication" },
    },
    {
      rule: "impossible-travel-foreign",
      hit: { category: "authentication", outcome: "success", actor: { user: "root" }, location: { country: "RU" } },
      miss: { category: "authentication", outcome: "success", actor: { user: "root" }, location: { country: "US" } },
    },
  ];

  for (const c of cases) {
    it(`${c.rule}: hits the right event`, () => {
      expect(matchesRule(makeEvent(c.hit), byId(c.rule))).toBe(true);
    });
    it(`${c.rule}: misses the wrong event`, () => {
      expect(matchesRule(makeEvent(c.miss), byId(c.rule))).toBe(false);
    });
  }

  it("evaluate() splits windowed brute-force from single-event matches", () => {
    // A failed auth from a known-bad IP hits several single-event rules AND is a
    // brute-force window candidate.
    const ev = makeEvent({
      category: "authentication",
      outcome: "failure",
      actor: { ip: "203.0.113.9", user: "root" },
    });
    const { matched, windowCandidates } = evaluate(ev, rules);
    const matchedIds = matched.map((r) => r.id);
    expect(matchedIds).toContain("auth-failed-login");
    expect(matchedIds).toContain("known-bad-ip");
    expect(matchedIds).not.toContain("brute-force-logins");
    expect(windowCandidates.map((r) => r.id)).toContain("brute-force-logins");
  });
});
