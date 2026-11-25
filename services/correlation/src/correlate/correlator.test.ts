import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Alert } from "@avekshak/schema";
import { Correlator } from "./correlator.js";

// ---------------------------------------------------------------------------
// Redis fake — simulates SET NX lock, GET, SET, eval (release)
// ---------------------------------------------------------------------------

function makeRedisFake() {
  const store = new Map<string, string>();

  return {
    store,
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    set: vi.fn(async (key: string, value: string, ...args: unknown[]) => {
      const nxIndex = args.indexOf("NX");
      if (nxIndex !== -1) {
        if (store.has(key)) return null;
        store.set(key, value);
        return "OK";
      }
      store.set(key, value);
      return "OK";
    }),
    eval: vi.fn(async (_script: string, _numkeys: number, key: string, token: string) => {
      if (store.get(key) === token) {
        store.delete(key);
        return 1;
      }
      return 0;
    }),
    quit: vi.fn().mockResolvedValue("OK"),
  };
}

// ---------------------------------------------------------------------------
// DB fake — tracks incident inserts
// ---------------------------------------------------------------------------

function makeDbFake(insertedIncidents: Array<{ id: string }>) {
  return {
    insert: vi.fn((table: unknown) => ({
      values: vi.fn((row: { id?: string; alertId?: string }) => {
        if (table === "incidents_table" || insertedIncidents !== undefined) {
          if (row.id) insertedIncidents.push({ id: row.id });
        }
        return {
          onConflictDoNothing: vi.fn(() => ({
            returning: vi.fn().mockResolvedValue(
              row.alertId ? [{ alertId: row.alertId }] : [],
            ),
          })),
        };
      }),
    })),
    select: vi.fn(() => ({
      from: vi.fn(() => ({
        where: vi.fn(() => ({
          orderBy: vi.fn(() => ({
            limit: vi.fn().mockResolvedValue([]),
          })),
        })),
      })),
    })),
    update: vi.fn(() => ({
      set: vi.fn(() => ({
        where: vi.fn().mockResolvedValue([]),
      })),
    })),
  };
}

vi.mock("@avekshak/db", () => ({
  getDb: vi.fn(),
  incidents: "incidents_table",
  incidentAlerts: "incident_alerts_table",
}));

vi.mock("ioredis", () => ({
  Redis: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeAlert(over: Partial<Alert> = {}): Alert {
  return {
    id: "alert-1",
    eventId: "event-1",
    ruleId: "auth-failed-login",
    title: "Failed authentication",
    severity: 40,
    ts: "2026-06-01T02:00:00.000Z",
    actorIp: "203.0.113.42",
    ...over,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Correlator", () => {
  let redisFake: ReturnType<typeof makeRedisFake>;
  let insertedIncidents: Array<{ id: string }>;

  beforeEach(async () => {
    vi.resetAllMocks();
    redisFake = makeRedisFake();
    insertedIncidents = [];

    const { getDb } = await import("@avekshak/db");
    vi.mocked(getDb).mockReturnValue(makeDbFake(insertedIncidents) as never);
  });

  it("creates a new incident and links the alert on first correlate", async () => {
    const correlator = new Correlator(redisFake as never);
    const result = await correlator.correlate(makeAlert());

    expect(result.createdIncident).toBe(true);
    expect(result.linked).toBe(true);
    expect(typeof result.incidentId).toBe("string");
    expect(insertedIncidents).toHaveLength(1);
  });

  it("two concurrent correlate calls for the same key produce exactly one incident", async () => {
    // Both calls start simultaneously — the lock means only the first one
    // inserts an incident; the second sees the Redis cache entry and reuses it.
    const correlator = new Correlator(redisFake as never);

    const alert1 = makeAlert({ id: "alert-1" });
    const alert2 = makeAlert({ id: "alert-2" });

    const [r1, r2] = await Promise.all([
      correlator.correlate(alert1),
      correlator.correlate(alert2),
    ]);

    // Exactly one incident should have been created
    const createdCount = [r1, r2].filter((r) => r.createdIncident).length;
    expect(createdCount).toBe(1);

    // Both should reference the same incident
    expect(r1.incidentId).toBe(r2.incidentId);
  });

  it("second sequential call with same correlation key reuses the existing incident", async () => {
    const correlator = new Correlator(redisFake as never);
    const alert1 = makeAlert({ id: "alert-1" });
    const alert2 = makeAlert({ id: "alert-2" });

    const r1 = await correlator.correlate(alert1);
    const r2 = await correlator.correlate(alert2);

    expect(r1.createdIncident).toBe(true);
    expect(r2.createdIncident).toBe(false);
    expect(r1.incidentId).toBe(r2.incidentId);
    expect(insertedIncidents).toHaveLength(1);
  });

  it("alert with no correlatable identity gets its own singleton incident", async () => {
    const correlator = new Correlator(redisFake as never);
    const alert = makeAlert({
      id: "alert-singleton",
      actorIp: undefined,
      actorUser: undefined,
      targetHost: undefined,
    });

    const result = await correlator.correlate(alert);

    expect(result.createdIncident).toBe(true);
    expect(insertedIncidents).toHaveLength(1);
  });

  it("two alerts with no correlatable identity each get their own incident", async () => {
    const { getDb } = await import("@avekshak/db");

    // Fresh db fake for each call so each sees empty select result
    let callCount = 0;
    vi.mocked(getDb).mockImplementation(() => {
      callCount++;
      return makeDbFake(insertedIncidents) as never;
    });

    const correlator = new Correlator(redisFake as never);

    await correlator.correlate(
      makeAlert({ id: "alert-a", actorIp: undefined, actorUser: undefined, targetHost: undefined }),
    );
    await correlator.correlate(
      makeAlert({ id: "alert-b", actorIp: undefined, actorUser: undefined, targetHost: undefined }),
    );

    expect(insertedIncidents).toHaveLength(2);
    expect(insertedIncidents[0].id).not.toBe(insertedIncidents[1].id);
  });
});
