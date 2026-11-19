import { describe, it, expect } from "vitest";
import { canTransition } from "./lifecycle.js";

describe("canTransition", () => {
  it("allows the linear happy path", () => {
    expect(canTransition("open", "triaged")).toBe(true);
    expect(canTransition("triaged", "approved")).toBe(true);
    expect(canTransition("triaged", "rejected")).toBe(true);
    expect(canTransition("approved", "closed")).toBe(true);
    expect(canTransition("rejected", "closed")).toBe(true);
  });

  it("rejects skipping triage", () => {
    expect(canTransition("open", "approved")).toBe(false);
    expect(canTransition("open", "closed")).toBe(false);
  });

  it("rejects moving backwards", () => {
    expect(canTransition("triaged", "open")).toBe(false);
    expect(canTransition("approved", "triaged")).toBe(false);
  });

  it("treats closed as terminal", () => {
    expect(canTransition("closed", "open")).toBe(false);
    expect(canTransition("closed", "triaged")).toBe(false);
    expect(canTransition("closed", "approved")).toBe(false);
  });

  it("rejects approving and rejecting the same incident path confusion", () => {
    expect(canTransition("approved", "rejected")).toBe(false);
    expect(canTransition("rejected", "approved")).toBe(false);
  });
});
