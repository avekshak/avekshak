import { describe, it, expect } from "vitest";
import { triageWithRetry } from "./prompt.js";
import { LlmOutputError, type IncidentContext } from "./provider.js";

const ctx: IncidentContext = {
  incidentId: "11111111-1111-1111-1111-111111111111",
  title: "test incident",
  severity: 40,
  correlationKey: "ip:203.0.113.9",
  createdAt: "2026-06-01T02:00:00.000Z",
  alerts: [],
  events: [],
};

const validJson = JSON.stringify({
  verdict: "suspicious",
  confidence: 70,
  rationale: "repeated failures",
  recommendedAction: "review source IP",
});

describe("triageWithRetry", () => {
  it("returns the verdict on the first valid response", async () => {
    let calls = 0;
    const v = await triageWithRetry(ctx, "fake", async () => {
      calls += 1;
      return validJson;
    });
    expect(calls).toBe(1);
    expect(v.verdict).toBe("suspicious");
  });

  it("retries past malformed output and then succeeds", async () => {
    const replies = ["not json", "{ half", validJson];
    let calls = 0;
    const v = await triageWithRetry(ctx, "fake", async () => replies[calls++]);
    expect(calls).toBe(3);
    expect(v.confidence).toBe(70);
  });

  it("sends a correction nudge on retries, not on the first call", async () => {
    const prompts: string[] = [];
    await triageWithRetry(ctx, "fake", async (userPrompt) => {
      prompts.push(userPrompt);
      return prompts.length < 2 ? "garbage" : validJson;
    });
    expect(prompts[0]).not.toContain("could not be parsed");
    expect(prompts[1]).toContain("could not be parsed");
  });

  it("throws LlmOutputError (does not crash) after exhausting attempts", async () => {
    await expect(
      triageWithRetry(ctx, "fake", async () => "never valid"),
    ).rejects.toBeInstanceOf(LlmOutputError);
  });

  it("surfaces the last raw output on the error for debugging", async () => {
    try {
      await triageWithRetry(ctx, "fake", async () => "still bad", 2);
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(LlmOutputError);
      expect((err as LlmOutputError).raw).toBe("still bad");
    }
  });
});
