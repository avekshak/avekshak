import { describe, it, expect } from "vitest";
import { loadRules } from "../src/rule-loader.js";
import { evaluateRules } from "../src/evaluator.js";
import { join } from "path";
import type { NormalizedEvent } from "@avekshak/schema";

const RULES_DIR = join(import.meta.dirname, "../rules");

const baseEvent: NormalizedEvent = {
  id: "00000000-0000-0000-0000-000000000001",
  ts: "2026-11-10T02:00:00.000Z",
  source: "syslog",
  category: "authentication",
  action: "login_failed",
  outcome: "failure",
  severity: 40,
  actor: { ip: "1.2.3.4", user: "admin" },
  target: { host: "web-01" },
  raw: {},
};

// ── Rule Loader ───────────────────────────────────────────────────────────────

describe("loadRules", () => {
  it("loads all valid YAML rules", async () => {
    const rules = await loadRules(RULES_DIR);
    expect(rules.length).toBeGreaterThanOrEqual(6);
    for (const rule of rules) {
      expect(rule.id).toBeTruthy();
      expect(rule.severity).toBeGreaterThanOrEqual(0);
      expect(rule.severity).toBeLessThanOrEqual(100);
    }
  });

  it("returns empty array for non-existent directory", async () => {
    const rules = await loadRules("/tmp/no-such-dir");
    expect(rules).toEqual([]);
  });

  it("rejects rules with missing required fields", async () => {
    // Inline bad YAML via a temp approach — verify schema rejects it
    const { RuleSchema } = await import("../src/rule-schema.js");
    const result = RuleSchema.safeParse({ id: "BAD", title: "Bad rule" });
    expect(result.success).toBe(false);
  });
});

// ── Evaluator ─────────────────────────────────────────────────────────────────

describe("evaluateRules", () => {
  it("matches AV-001 for login_failed action", async () => {
    const rules = await loadRules(RULES_DIR);
    const matched = evaluateRules(baseEvent, rules);
    const ids = matched.map((r) => r.id);
    expect(ids).toContain("AV-001");
  });

  it("does not match AV-001 for login_success action", async () => {
    const rules = await loadRules(RULES_DIR);
    const event = { ...baseEvent, action: "login_success", outcome: "success" as const };
    const matched = evaluateRules(event, rules);
    const ids = matched.map((r) => r.id);
    expect(ids).not.toContain("AV-001");
  });

  it("matches AV-005 for data_access category", async () => {
    const rules = await loadRules(RULES_DIR);
    const event = { ...baseEvent, category: "data_access", action: "get_object" };
    const matched = evaluateRules(event, rules);
    expect(matched.map((r) => r.id)).toContain("AV-005");
  });

  it("matches AV-006 for severity >= 80", async () => {
    const rules = await loadRules(RULES_DIR);
    const event = { ...baseEvent, severity: 85 };
    const matched = evaluateRules(event, rules);
    expect(matched.map((r) => r.id)).toContain("AV-006");
  });

  it("does not match AV-006 for severity < 80", async () => {
    const rules = await loadRules(RULES_DIR);
    const event = { ...baseEvent, severity: 50 };
    const matched = evaluateRules(event, rules);
    expect(matched.map((r) => r.id)).not.toContain("AV-006");
  });

  it("skips threshold rules (AV-002)", async () => {
    const rules = await loadRules(RULES_DIR);
    const matched = evaluateRules(baseEvent, rules);
    expect(matched.map((r) => r.id)).not.toContain("AV-002");
  });

  it("matches AV-004 for failure outcome", async () => {
    const rules = await loadRules(RULES_DIR);
    const event = { ...baseEvent, action: "assume_role", outcome: "failure" as const };
    const matched = evaluateRules(event, rules);
    expect(matched.map((r) => r.id)).toContain("AV-004");
  });
});
