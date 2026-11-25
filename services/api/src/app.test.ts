import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { buildApp } from "./app.js";
import {
  listIncidents,
  getIncidentDetail,
  decideIncident,
  listAlerts,
  listEvents,
  IncidentNotFoundError,
  InvalidDecisionStateError,
} from "./incidents.js";
import { planResponse } from "./response.js";
import type { Incident } from "@avekshak/schema";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock("./incidents.js", () => ({
  listIncidents: vi.fn(),
  getIncidentDetail: vi.fn(),
  decideIncident: vi.fn(),
  listAlerts: vi.fn(),
  listEvents: vi.fn(),
  IncidentNotFoundError: class IncidentNotFoundError extends Error {
    constructor(id: string) {
      super(`incident not found: ${id}`);
      this.name = "IncidentNotFoundError";
    }
  },
  InvalidDecisionStateError: class InvalidDecisionStateError extends Error {
    constructor(id: string, readonly currentStatus: string) {
      super(`incident ${id} is '${currentStatus}', not 'triaged'; cannot decide`);
      this.name = "InvalidDecisionStateError";
    }
  },
}));

vi.mock("ioredis", () => {
  const Redis = vi.fn(() => ({
    status: "ready",
    ping: vi.fn().mockResolvedValue("PONG"),
    disconnect: vi.fn(),
    connect: vi.fn(),
  }));
  return { Redis };
});

vi.mock("@avekshak/db", () => ({
  getDb: vi.fn(() => ({ execute: vi.fn().mockResolvedValue([]) })),
  closeDb: vi.fn(),
  incidents: {},
  alerts: {},
  incidentAlerts: {},
  events: {},
  approvals: {},
  appendLedger: vi.fn(),
  readLedger: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const baseIncident: Incident = {
  id: "inc-1",
  title: "Brute force from 203.0.113.9",
  status: "triaged",
  severity: 70,
  correlationKey: "ip:203.0.113.9",
  verdict: null,
  createdAt: "2026-06-01T00:00:00.000Z",
  updatedAt: "2026-06-01T00:05:00.000Z",
};

// ---------------------------------------------------------------------------
// 1. planResponse — pure function, no DB
// ---------------------------------------------------------------------------

describe("planResponse", () => {
  it("returns block_ip action with the extracted IP when correlationKey is ip-based", () => {
    const result = planResponse(baseIncident);
    expect(result.dryRun).toBe(true);
    expect(result.action).toBe("block_ip");
    expect(result.target).toBe("203.0.113.9");
    expect(result.detail).toContain("203.0.113.9");
  });

  it("returns notify_only when correlationKey has no IP prefix", () => {
    const result = planResponse({ ...baseIncident, correlationKey: "host:db-prod-1" });
    expect(result.action).toBe("notify_only");
    expect(result.target).toBeNull();
    expect(result.detail).toContain("notify");
  });

  it("always sets dryRun: true — the response never executes for real", () => {
    const ipResult = planResponse(baseIncident);
    const noIpResult = planResponse({ ...baseIncident, correlationKey: "user:root" });
    expect(ipResult.dryRun).toBe(true);
    expect(noIpResult.dryRun).toBe(true);
  });

  it("includes the incident title in the detail message", () => {
    const result = planResponse(baseIncident);
    expect(result.detail).toContain(baseIncident.title);
  });
});

// ---------------------------------------------------------------------------
// 2. IncidentNotFoundError
// ---------------------------------------------------------------------------

describe("IncidentNotFoundError", () => {
  it("is an instance of Error with the correct name", () => {
    const err = new IncidentNotFoundError("inc-99");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("IncidentNotFoundError");
  });

  it("includes the incident id in the message", () => {
    const err = new IncidentNotFoundError("inc-99");
    expect(err.message).toContain("inc-99");
  });
});

// ---------------------------------------------------------------------------
// 3. InvalidDecisionStateError
// ---------------------------------------------------------------------------

describe("InvalidDecisionStateError", () => {
  it("is an instance of Error with the correct name", () => {
    const err = new InvalidDecisionStateError("inc-1", "open");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("InvalidDecisionStateError");
  });

  it("exposes the currentStatus property", () => {
    const err = new InvalidDecisionStateError("inc-1", "approved");
    expect(err.currentStatus).toBe("approved");
  });

  it("includes both the incident id and status in the message", () => {
    const err = new InvalidDecisionStateError("inc-1", "open");
    expect(err.message).toContain("inc-1");
    expect(err.message).toContain("open");
  });
});

// ---------------------------------------------------------------------------
// HTTP route tests via Fastify inject
// ---------------------------------------------------------------------------

describe("GET /health", () => {
  it("returns db and redis status", async () => {
    const app = buildApp();
    const res = await app.inject({ method: "GET", url: "/health" });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(typeof body.db).toBe("boolean");
    expect(typeof body.redis).toBe("boolean");
  });
});

describe("GET /incidents", () => {
  beforeEach(() => {
    vi.mocked(listIncidents).mockResolvedValue([baseIncident]);
  });
  afterEach(() => vi.resetAllMocks());

  it("returns a list of incidents under the incidents key", async () => {
    const app = buildApp();
    const res = await app.inject({ method: "GET", url: "/incidents" });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(Array.isArray(body.incidents)).toBe(true);
    expect(body.incidents).toHaveLength(1);
    expect(body.incidents[0].id).toBe("inc-1");
  });

  it("returns an empty array when there are no incidents", async () => {
    vi.mocked(listIncidents).mockResolvedValue([]);
    const app = buildApp();
    const res = await app.inject({ method: "GET", url: "/incidents" });
    expect(res.statusCode).toBe(200);
    expect(res.json().incidents).toHaveLength(0);
  });
});

describe("GET /incidents/:id", () => {
  const detail = { ...baseIncident, alerts: [], events: [], ledger: [] };

  afterEach(() => vi.resetAllMocks());

  it("returns full incident detail for a known id", async () => {
    vi.mocked(getIncidentDetail).mockResolvedValue(detail);
    const app = buildApp();
    const res = await app.inject({ method: "GET", url: "/incidents/inc-1" });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.id).toBe("inc-1");
    expect(Array.isArray(body.alerts)).toBe(true);
    expect(Array.isArray(body.ledger)).toBe(true);
  });

  it("returns 404 when the incident does not exist", async () => {
    vi.mocked(getIncidentDetail).mockRejectedValue(new IncidentNotFoundError("inc-99"));
    const app = buildApp();
    const res = await app.inject({ method: "GET", url: "/incidents/inc-99" });
    expect(res.statusCode).toBe(404);
    const body = res.json();
    expect(body.error).toBe("incident_not_found");
    expect(body.id).toBe("inc-99");
  });
});

describe("POST /incidents/:id/approve", () => {
  afterEach(() => vi.resetAllMocks());

  it("approves a triaged incident and returns the decision result", async () => {
    const mockResult = {
      approval: { id: "ap-1", incidentId: "inc-1", decision: "approved", decidedBy: "operator", decidedAt: "2026-06-01T01:00:00.000Z" },
      incidentId: "inc-1",
      status: "approved" as const,
      response: planResponse(baseIncident),
    };
    vi.mocked(decideIncident).mockResolvedValue(mockResult);
    const app = buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/incidents/inc-1/approve",
      payload: { decidedBy: "analyst-1" },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.status).toBe("approved");
    expect(body.response).not.toBeNull();
    expect(vi.mocked(decideIncident)).toHaveBeenCalledWith("inc-1", "approved", "analyst-1", undefined);
  });

  it("defaults decidedBy to 'operator' when body is omitted", async () => {
    vi.mocked(decideIncident).mockResolvedValue({
      approval: { id: "ap-2", incidentId: "inc-1", decision: "approved", decidedBy: "operator", decidedAt: "2026-06-01T01:00:00.000Z" },
      incidentId: "inc-1",
      status: "approved" as const,
      response: null,
    });
    const app = buildApp();
    await app.inject({ method: "POST", url: "/incidents/inc-1/approve" });
    expect(vi.mocked(decideIncident)).toHaveBeenCalledWith("inc-1", "approved", "operator", undefined);
  });

  it("returns 404 when the incident does not exist", async () => {
    vi.mocked(decideIncident).mockRejectedValue(new IncidentNotFoundError("inc-99"));
    const app = buildApp();
    const res = await app.inject({ method: "POST", url: "/incidents/inc-99/approve" });
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe("incident_not_found");
  });

  it("returns 409 when the incident is not in triaged state", async () => {
    vi.mocked(decideIncident).mockRejectedValue(new InvalidDecisionStateError("inc-1", "approved"));
    const app = buildApp();
    const res = await app.inject({ method: "POST", url: "/incidents/inc-1/approve" });
    expect(res.statusCode).toBe(409);
    const body = res.json();
    expect(body.error).toBe("invalid_decision_state");
    expect(body.status).toBe("approved");
  });
});

describe("POST /incidents/:id/reject", () => {
  afterEach(() => vi.resetAllMocks());

  it("rejects a triaged incident and returns null response — the gate stops here", async () => {
    const mockResult = {
      approval: { id: "ap-3", incidentId: "inc-1", decision: "rejected", decidedBy: "operator", decidedAt: "2026-06-01T01:00:00.000Z" },
      incidentId: "inc-1",
      status: "rejected" as const,
      response: null,
    };
    vi.mocked(decideIncident).mockResolvedValue(mockResult);
    const app = buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/incidents/inc-1/reject",
      payload: { decidedBy: "analyst-1", note: "false positive" },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.status).toBe("rejected");
    expect(body.response).toBeNull();
    expect(vi.mocked(decideIncident)).toHaveBeenCalledWith("inc-1", "rejected", "analyst-1", "false positive");
  });

  it("returns 404 when the incident does not exist", async () => {
    vi.mocked(decideIncident).mockRejectedValue(new IncidentNotFoundError("inc-99"));
    const app = buildApp();
    const res = await app.inject({ method: "POST", url: "/incidents/inc-99/reject" });
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe("incident_not_found");
  });

  it("returns 409 when the incident is already decided", async () => {
    vi.mocked(decideIncident).mockRejectedValue(new InvalidDecisionStateError("inc-1", "rejected"));
    const app = buildApp();
    const res = await app.inject({ method: "POST", url: "/incidents/inc-1/reject" });
    expect(res.statusCode).toBe(409);
    const body = res.json();
    expect(body.error).toBe("invalid_decision_state");
    expect(body.status).toBe("rejected");
  });
});

// ---------------------------------------------------------------------------
// Fixtures for alerts / events
// ---------------------------------------------------------------------------

const baseAlert = {
  id: "alert-1",
  eventId: "event-1",
  ruleId: "auth-failed-login",
  title: "Failed authentication",
  severity: 40,
  ts: "2026-06-01T02:00:00.000Z",
  actorIp: "203.0.113.42",
};

const baseEvent = {
  id: "event-1",
  ts: "2026-06-01T02:00:00.000Z",
  source: "syslog" as const,
  category: "authentication",
  action: "login_failed",
  outcome: "failure" as const,
  severity: 14,
  actor: { ip: "203.0.113.42" },
  target: {},
  raw: { line: "<38>Nov 25 15:28:41 host target-app: Failed login" },
};

// ---------------------------------------------------------------------------
// GET /alerts
// ---------------------------------------------------------------------------

describe("GET /alerts", () => {
  beforeEach(() => {
    vi.mocked(listAlerts).mockResolvedValue([baseAlert]);
  });
  afterEach(() => vi.resetAllMocks());

  it("returns a list of alerts under the alerts key", async () => {
    const app = buildApp();
    const res = await app.inject({ method: "GET", url: "/alerts" });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(Array.isArray(body.alerts)).toBe(true);
    expect(body.alerts).toHaveLength(1);
    expect(body.alerts[0].id).toBe("alert-1");
  });

  it("returns an empty array when there are no alerts", async () => {
    vi.mocked(listAlerts).mockResolvedValue([]);
    const app = buildApp();
    const res = await app.inject({ method: "GET", url: "/alerts" });
    expect(res.statusCode).toBe(200);
    expect(res.json().alerts).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// GET /events
// ---------------------------------------------------------------------------

describe("GET /events", () => {
  beforeEach(() => {
    vi.mocked(listEvents).mockResolvedValue([baseEvent]);
  });
  afterEach(() => vi.resetAllMocks());

  it("returns a list of events under the events key", async () => {
    const app = buildApp();
    const res = await app.inject({ method: "GET", url: "/events" });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(Array.isArray(body.events)).toBe(true);
    expect(body.events).toHaveLength(1);
    expect(body.events[0].id).toBe("event-1");
  });

  it("returns an empty array when there are no events", async () => {
    vi.mocked(listEvents).mockResolvedValue([]);
    const app = buildApp();
    const res = await app.inject({ method: "GET", url: "/events" });
    expect(res.statusCode).toBe(200);
    expect(res.json().events).toHaveLength(0);
  });
});
