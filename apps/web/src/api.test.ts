import { describe, it, expect, vi, beforeEach } from "vitest";
import { listAlerts, listEvents, listIncidents, ApiError } from "./api.js";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function ok(body: unknown) {
  return Promise.resolve({ ok: true, json: () => Promise.resolve(body) } as Response);
}

function fail(status: number, body: unknown) {
  return Promise.resolve({
    ok: false,
    status,
    json: () => Promise.resolve(body),
  } as Response);
}

beforeEach(() => mockFetch.mockReset());

describe("listAlerts", () => {
  it("returns alerts array from /api/alerts", async () => {
    const alert = { id: "a1", title: "ssh brute force", severity: 3 };
    mockFetch.mockReturnValueOnce(ok({ alerts: [alert] }));
    const result = await listAlerts();
    expect(result).toEqual([alert]);
    expect(mockFetch).toHaveBeenCalledWith("/api/alerts", expect.any(Object));
  });

  it("returns empty array when no alerts", async () => {
    mockFetch.mockReturnValueOnce(ok({ alerts: [] }));
    expect(await listAlerts()).toEqual([]);
  });
});

describe("listEvents", () => {
  it("returns events array from /api/events", async () => {
    const event = { id: "e1", ts: "2024-01-01T00:00:00Z", raw: { line: "sshd auth failed" } };
    mockFetch.mockReturnValueOnce(ok({ events: [event] }));
    const result = await listEvents();
    expect(result).toEqual([event]);
    expect(mockFetch).toHaveBeenCalledWith("/api/events", expect.any(Object));
  });
});

describe("listIncidents", () => {
  it("returns incidents array from /api/incidents", async () => {
    const incident = { id: "i1", title: "SSH Brute Force", status: "triaged", severity: 3 };
    mockFetch.mockReturnValueOnce(ok({ incidents: [incident] }));
    expect(await listIncidents()).toEqual([incident]);
  });
});

describe("ApiError", () => {
  it("throws ApiError with status and code on non-ok response", async () => {
    mockFetch.mockReturnValueOnce(fail(404, { error: "incident_not_found" }));
    await expect(listIncidents()).rejects.toMatchObject({
      name: "ApiError",
      status: 404,
      code: "incident_not_found",
    });
  });
});
