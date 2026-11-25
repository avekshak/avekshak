import { describe, it, expect, vi, afterEach } from "vitest";

const { mockCreate } = vi.hoisted(() => {
  const mockCreate = vi.fn();
  return { mockCreate };
});

vi.mock("@anthropic-ai/sdk", () => ({
  default: vi.fn(() => ({ messages: { create: mockCreate } })),
}));

import { ClaudeProvider } from "./claude.js";

const validVerdict = JSON.stringify({
  verdict: "benign",
  confidence: 85,
  rationale: "normal traffic pattern",
  recommendedAction: "no action needed",
});

const ctx = {
  incidentId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  title: "test",
  severity: 20,
  correlationKey: "ip:192.0.2.1",
  createdAt: "2026-01-01T00:00:00.000Z",
  alerts: [],
  events: [],
};

afterEach(() => {
  mockCreate.mockReset();
  delete process.env.CLAUDE_MODEL;
});

describe("ClaudeProvider constructor", () => {
  it("throws when ANTHROPIC_API_KEY is not set", () => {
    const saved = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    expect(() => new ClaudeProvider()).toThrow("ANTHROPIC_API_KEY is not set");
    if (saved) process.env.ANTHROPIC_API_KEY = saved;
  });

  it("accepts an explicit apiKey option", () => {
    expect(() => new ClaudeProvider({ apiKey: "sk-test" })).not.toThrow();
  });

  it("uses the model option when provided", () => {
    const p = new ClaudeProvider({ apiKey: "sk-test", model: "my-model" });
    expect((p as unknown as { model: string }).model).toBe("my-model");
  });

  it("falls back to CLAUDE_MODEL env var", () => {
    process.env.CLAUDE_MODEL = "env-model";
    const p = new ClaudeProvider({ apiKey: "sk-test" });
    expect((p as unknown as { model: string }).model).toBe("env-model");
  });

  it("defaults to claude-haiku-4-5-20251001", () => {
    const p = new ClaudeProvider({ apiKey: "sk-test" });
    expect((p as unknown as { model: string }).model).toBe(
      "claude-haiku-4-5-20251001",
    );
  });
});

describe("ClaudeProvider.triage", () => {
  it("returns a parsed verdict from the API response", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: validVerdict }],
    });
    const p = new ClaudeProvider({ apiKey: "sk-test" });
    const v = await p.triage(ctx);
    expect(v.verdict).toBe("benign");
    expect(v.confidence).toBe(85);
  });

  it("passes the configured model to messages.create", async () => {
    mockCreate.mockResolvedValue({
      content: [{ type: "text", text: validVerdict }],
    });
    const p = new ClaudeProvider({ apiKey: "sk-test", model: "claude-custom" });
    await p.triage(ctx);
    expect(mockCreate).toHaveBeenCalledWith(
      expect.objectContaining({ model: "claude-custom" }),
    );
  });
});

describe("ClaudeProvider.close", () => {
  it("resolves without error", async () => {
    const p = new ClaudeProvider({ apiKey: "sk-test" });
    await expect(p.close()).resolves.toBeUndefined();
  });
});
