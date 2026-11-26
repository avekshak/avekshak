import { describe, it, expect, vi, beforeEach } from "vitest";
import { ApiError, listAlerts, listEvents, listIncidents } from "./api.js";

// ---------------------------------------------------------------------------
// Stub global fetch
// ---------------------------------------------------------------------------

function mockFetch(body: unknown, status = 200) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
    }),
  );
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// ApiError
// ---------------------------------------------------------------------------

describe("ApiError", () => {
  it("carries status and message", () => {
    const err = new ApiError(404, "not found", "incident_not_found");
    expect(err.status).toBe(404);
    expect(err.message).toBe("not found");
    expect(err.code).toBe("incident_not_found");
    expect(err.name).toBe("ApiError");
  });
});

// ---------------------------------------------------------------------------
// listIncidents
// ---------------------------------------------------------------------------

describe("listIncidents", () => {
  it("returns the incidents array from the response", async () => {
    const incident = {
      id: "abc", title: "Test", status: "open", severity: 70,
      correlationKey: "ip:1.2.3.4", verdict: null,
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    };
    mockFetch({ incidents: [incident] });
    const result = await listIncidents();
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("abc");
  });

  it("throws ApiError on non-ok response", async () => {
    mockFetch({ error: "server_error" }, 500);
    await expect(listIncidents()).rejects.toBeInstanceOf(ApiError);
  });
});

// ---------------------------------------------------------------------------
// listAlerts
// ---------------------------------------------------------------------------

describe("listAlerts", () => {
  it("returns alerts array", async () => {
    const alert = {
      id: "a1", eventId: "e1", ruleId: "brute-force",
      title: "Brute force", severity: 70,
      ts: new Date().toISOString(), actorIp: "1.2.3.4",
    };
    mockFetch({ alerts: [alert] });
    const result = await listAlerts();
    expect(result).toHaveLength(1);
    expect(result[0].ruleId).toBe("brute-force");
  });

  it("returns empty array when no alerts", async () => {
    mockFetch({ alerts: [] });
    const result = await listAlerts();
    expect(result).toEqual([]);
  });

  it("throws ApiError on failure", async () => {
    mockFetch({ error: "db_error" }, 500);
    await expect(listAlerts()).rejects.toBeInstanceOf(ApiError);
  });
});

// ---------------------------------------------------------------------------
// listEvents
// ---------------------------------------------------------------------------

describe("listEvents", () => {
  it("returns events array", async () => {
    const event = {
      id: "ev1", ts: new Date().toISOString(),
      source: "syslog", category: "authentication",
      action: "login_failed", outcome: "failure", severity: 40,
      actor: { ip: "1.2.3.4" }, target: {},
      raw: { line: "<38>Nov 26 sshd: Failed password" },
    };
    mockFetch({ events: [event] });
    const result = await listEvents();
    expect(result).toHaveLength(1);
    expect(result[0].source).toBe("syslog");
    expect(result[0].raw).toEqual({ line: "<38>Nov 26 sshd: Failed password" });
  });

  it("returns empty array when no events", async () => {
    mockFetch({ events: [] });
    const result = await listEvents();
    expect(result).toEqual([]);
  });

  it("throws ApiError on failure", async () => {
    mockFetch({ error: "db_error" }, 500);
    await expect(listEvents()).rejects.toBeInstanceOf(ApiError);
  });
});
