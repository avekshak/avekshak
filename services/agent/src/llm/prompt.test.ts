import { describe, it, expect } from "vitest";
import {
  buildUserPrompt,
  extractJsonObject,
  parseVerdict,
  SYSTEM_PROMPT,
} from "./prompt.js";
import type { IncidentContext } from "./provider.js";

const ctx: IncidentContext = {
  incidentId: "11111111-1111-1111-1111-111111111111",
  title: "Failed authentication from 203.0.113.9",
  severity: 40,
  correlationKey: "ip:203.0.113.9",
  createdAt: "2026-06-01T02:00:00.000Z",
  alerts: [
    {
      id: "22222222-2222-2222-2222-222222222222",
      eventId: "33333333-3333-3333-3333-333333333333",
      ruleId: "auth-failed-login",
      title: "Failed login",
      severity: 40,
      ts: "2026-06-01T02:00:00.000Z",
      actorIp: "203.0.113.9",
      actorUser: "root",
      targetHost: "db-prod-1",
    },
  ],
  events: [
    {
      id: "33333333-3333-3333-3333-333333333333",
      ts: "2026-06-01T02:00:00.000Z",
      source: "syslog",
      category: "authentication",
      action: "login_failed",
      outcome: "failure",
      severity: 40,
      actor: { user: "root", ip: "203.0.113.9" },
      target: { host: "db-prod-1" },
      raw: { msg: "sshd: failed password for root" },
    },
  ],
};

describe("buildUserPrompt", () => {
  it("includes the incident id, alerts, and events, and omits the raw blob", () => {
    const prompt = buildUserPrompt(ctx);
    expect(prompt).toContain(ctx.incidentId);
    expect(prompt).toContain("auth-failed-login");
    expect(prompt).toContain("login_failed");
    // The untouched vendor payload is dropped to keep the prompt lean.
    expect(prompt).not.toContain("sshd: failed password");
  });

  it("is deterministic for the same context", () => {
    expect(buildUserPrompt(ctx)).toBe(buildUserPrompt(ctx));
  });
});

describe("SYSTEM_PROMPT", () => {
  it("pins the JSON contract and the human-approval constraint", () => {
    expect(SYSTEM_PROMPT).toContain("verdict");
    expect(SYSTEM_PROMPT).toContain("confidence");
    expect(SYSTEM_PROMPT).toContain("recommendedAction");
    expect(SYSTEM_PROMPT.toLowerCase()).toContain("human approves");
  });
});

describe("extractJsonObject", () => {
  it("returns a bare object unchanged", () => {
    expect(extractJsonObject('{"a":1}')).toBe('{"a":1}');
  });

  it("pulls the object out of a ```json fence", () => {
    const text = 'Here you go:\n```json\n{"verdict":"benign"}\n```\nthanks';
    expect(extractJsonObject(text)).toBe('{"verdict":"benign"}');
  });

  it("handles braces inside strings", () => {
    const text = '{"rationale":"saw a { brace } in a message"}';
    expect(extractJsonObject(text)).toBe(text);
  });

  it("returns null when there is no object", () => {
    expect(extractJsonObject("no json here")).toBeNull();
  });
});

describe("parseVerdict", () => {
  const good = {
    verdict: "critical",
    confidence: 92,
    rationale: "S3 exfiltration finding from a foreign region",
    recommendedAction: "Isolate the bucket and rotate credentials",
  };

  it("parses a clean JSON object", () => {
    expect(parseVerdict(JSON.stringify(good))).toEqual(good);
  });

  it("parses JSON wrapped in prose and a fence", () => {
    const raw = `Sure — my assessment:\n\`\`\`json\n${JSON.stringify(good)}\n\`\`\``;
    expect(parseVerdict(raw)).toEqual(good);
  });

  it("returns null on a missing required field", () => {
    const { confidence: _omit, ...bad } = good;
    expect(parseVerdict(JSON.stringify(bad))).toBeNull();
  });

  it("returns null on an out-of-range confidence", () => {
    expect(parseVerdict(JSON.stringify({ ...good, confidence: 150 }))).toBeNull();
  });

  it("returns null on an unknown verdict label", () => {
    expect(parseVerdict(JSON.stringify({ ...good, verdict: "scary" }))).toBeNull();
  });

  it("returns null on non-JSON text", () => {
    expect(parseVerdict("the model refused")).toBeNull();
  });
});
