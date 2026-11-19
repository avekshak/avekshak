import { describe, it, expect } from "vitest";
import type { NormalizedEvent, Rule } from "@avekshak/schema";
import { buildAlert, dedupeKey, DEDUPE_WINDOW_MS } from "./promote.js";

const rule: Rule = {
  id: "auth-failed-login",
  title: "Failed authentication",
  severity: 40,
  enabled: true,
  when: [{ field: "outcome", op: "eq", value: "failure" }],
};

function ev(over: Partial<NormalizedEvent> = {}): NormalizedEvent {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    ts: "2026-06-01T02:00:00.000Z",
    source: "syslog",
    category: "authentication",
    action: "login_failed",
    outcome: "failure",
    severity: 40,
    actor: { user: "root", ip: "203.0.113.9" },
    target: { host: "db-prod-1" },
    raw: {},
    ...over,
  };
}

describe("buildAlert", () => {
  it("builds an alert attributed to the rule", () => {
    const { alert } = buildAlert(ev(), rule);
    expect(alert.ruleId).toBe("auth-failed-login");
    expect(alert.title).toBe("Failed authentication");
    expect(alert.severity).toBe(40); // rule severity, not event
    expect(alert.actorIp).toBe("203.0.113.9");
    expect(alert.eventId).toBe(ev().id);
  });

  it("is idempotent: same event+rule → same alert id", () => {
    expect(buildAlert(ev(), rule).alert.id).toBe(buildAlert(ev(), rule).alert.id);
  });
});

describe("dedupeKey", () => {
  it("collapses events within the same window bucket", () => {
    const a = dedupeKey(ev({ ts: "2026-06-01T02:00:00.000Z" }), rule);
    const b = dedupeKey(ev({ ts: "2026-06-01T02:04:59.000Z" }), rule);
    expect(a).toBe(b); // same 5-min bucket, same actor/target/rule
  });

  it("separates events in different window buckets", () => {
    const a = dedupeKey(ev({ ts: "2026-06-01T02:00:00.000Z" }), rule);
    const b = dedupeKey(
      ev({ ts: new Date(Date.parse("2026-06-01T02:00:00.000Z") + DEDUPE_WINDOW_MS).toISOString() }),
      rule,
    );
    expect(a).not.toBe(b);
  });

  it("separates different actors", () => {
    const a = dedupeKey(ev({ actor: { ip: "1.1.1.1" } }), rule);
    const b = dedupeKey(ev({ actor: { ip: "2.2.2.2" } }), rule);
    expect(a).not.toBe(b);
  });

  it("separates different rules", () => {
    const other: Rule = { ...rule, id: "known-bad-ip" };
    expect(dedupeKey(ev(), rule)).not.toBe(dedupeKey(ev(), other));
  });
});
