import { describe, it, expect } from "vitest";
import { loadRulesFromString, RuleLoadError } from "./loader.js";

describe("loadRulesFromString", () => {
  it("loads a single rule mapping", () => {
    const yaml = `
id: failed-login
title: Failed login
severity: 40
when:
  - field: category
    op: eq
    value: authentication
  - field: outcome
    op: eq
    value: failure
`;
    const rules = loadRulesFromString(yaml);
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe("failed-login");
    expect(rules[0].enabled).toBe(true); // default applied
    expect(rules[0].when).toHaveLength(2);
  });

  it("loads a list of rules", () => {
    const yaml = `
- id: r1
  title: One
  severity: 10
  when:
    - { field: action, op: eq, value: login_failed }
- id: r2
  title: Two
  severity: 20
  enabled: false
  when:
    - { field: actor.ip, op: in, value: ["1.2.3.4", "5.6.7.8"] }
`;
    const rules = loadRulesFromString(yaml);
    expect(rules.map((r) => r.id)).toEqual(["r1", "r2"]);
    expect(rules[1].enabled).toBe(false);
  });

  it("parses a windowed rule", () => {
    const yaml = `
id: brute-force
title: Brute force
severity: 70
when:
  - { field: category, op: eq, value: authentication }
  - { field: outcome, op: eq, value: failure }
window:
  groupBy: actor.ip
  threshold: 5
  seconds: 300
`;
    const [rule] = loadRulesFromString(yaml);
    expect(rule.window).toEqual({
      groupBy: "actor.ip",
      threshold: 5,
      seconds: 300,
    });
  });

  it("returns [] for an empty document", () => {
    expect(loadRulesFromString("")).toEqual([]);
    expect(loadRulesFromString("# just a comment\n")).toEqual([]);
  });

  it("rejects invalid YAML with a clear error", () => {
    expect(() => loadRulesFromString("id: [unclosed", "bad.yaml")).toThrow(
      RuleLoadError,
    );
    expect(() => loadRulesFromString("id: [unclosed", "bad.yaml")).toThrow(
      /bad\.yaml: invalid YAML/,
    );
  });

  it("rejects a rule missing required fields with a pathed error", () => {
    const yaml = `
id: broken
title: No conditions
severity: 10
`;
    expect(() => loadRulesFromString(yaml, "broken.yaml")).toThrow(
      /broken\.yaml: rule\[0\] invalid at "when"/,
    );
  });

  it("rejects an unknown operator", () => {
    const yaml = `
id: bad-op
title: Bad op
severity: 10
when:
  - { field: outcome, op: matches, value: x }
`;
    expect(() => loadRulesFromString(yaml, "op.yaml")).toThrow(RuleLoadError);
  });

  it("rejects out-of-range severity", () => {
    const yaml = `
id: sev
title: Sev
severity: 500
when:
  - { field: outcome, op: eq, value: failure }
`;
    expect(() => loadRulesFromString(yaml, "sev.yaml")).toThrow(
      /invalid at "severity"/,
    );
  });
});
