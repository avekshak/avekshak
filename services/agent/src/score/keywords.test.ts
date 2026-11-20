import { describe, it, expect } from "vitest";
import {
  CRITICAL_KEYWORDS,
  HIGH_KEYWORDS,
  anyMatched,
  matched,
  matches,
  normalise,
} from "./keywords.js";

describe("normalise", () => {
  it("lowercases", () => {
    expect(normalise("ExFiltRATION")).toBe("exfiltration");
  });

  it("blanks a MAC address", () => {
    expect(normalise("00:1a:c2:3b:4c:5d")).not.toContain("c2");
  });

  it("blanks a UUID", () => {
    const uuid = "123e4567-e89b-12d3-a456-426614174000";
    expect(normalise(uuid).trim()).toBe("");
  });

  it("blanks a long hex digest / sha256", () => {
    const sha = "e".repeat(64);
    expect(normalise(sha).trim()).toBe("");
  });
});

describe("matches — whole words", () => {
  it("matches a plain critical keyword", () => {
    expect(matches(normalise("S3 Exfiltration detected"), "exfiltration")).toBe(true);
  });

  it("matches ransomware", () => {
    expect(matches(normalise("Ransomware note dropped"), "ransomware")).toBe(true);
  });

  it("matches a multi-word keyword", () => {
    expect(matches(normalise("observed lateral movement"), "lateral movement")).toBe(true);
  });
});

describe("matches — the #1607 bug must stay fixed", () => {
  it("'c2' does NOT match an AWS private hostname", () => {
    expect(matches(normalise("ip-10-0-1-7.ec2.internal"), "c2")).toBe(false);
  });

  it("'c2' does NOT match a MAC address octet", () => {
    expect(matches(normalise("mac 00:1a:c2:3b:4c:5d"), "c2")).toBe(false);
  });

  it("'c2' does NOT match inside a sha256", () => {
    expect(matches(normalise(`hash ${"c2".repeat(32)}`), "c2")).toBe(false);
  });

  it("'c2' DOES match when it stands alone as a token", () => {
    expect(matches(normalise("beaconing to c2 server"), "c2")).toBe(true);
  });
});

describe("matches — stems", () => {
  it("'beacon*' matches 'beaconing'", () => {
    expect(matches(normalise("c2 beaconing observed"), "beacon*")).toBe(true);
  });

  it("'credential dump*' matches 'credential dumping'", () => {
    expect(matches(normalise("credential dumping via lsass"), "credential dump*")).toBe(
      true,
    );
  });

  it("'exploit*' matches 'exploitation'", () => {
    expect(matches(normalise("active exploitation seen"), "exploit*")).toBe(true);
  });

  it("a whole-word keyword does NOT match inside a longer token", () => {
    // "malware" must not match inside "malwareless" via some stem accident.
    expect(matches(normalise("malwareless technique"), "malware")).toBe(false);
  });
});

describe("matched / anyMatched over the real vocabularies", () => {
  it("returns sorted display forms", () => {
    const text = normalise("Exfiltration and lateral movement, plus ransomware");
    expect(matched(text, CRITICAL_KEYWORDS)).toEqual([
      "exfiltration",
      "lateral movement",
      "ransomware",
    ]);
  });

  it("strips the stem marker from display output", () => {
    const text = normalise("c2 beaconing");
    expect(matched(text, CRITICAL_KEYWORDS)).toContain("beacon");
  });

  it("anyMatched is true for a high-keyword hit", () => {
    expect(anyMatched(normalise("brute force attempt"), HIGH_KEYWORDS)).toBe(true);
  });

  it("anyMatched is false for benign text", () => {
    expect(anyMatched(normalise("routine nightly backup completed"), CRITICAL_KEYWORDS)).toBe(
      false,
    );
    expect(anyMatched(normalise("routine nightly backup completed"), HIGH_KEYWORDS)).toBe(
      false,
    );
  });
});
