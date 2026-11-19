import Fastify, { type FastifyInstance } from "fastify";
import { getDb, closeDb } from "@avekshak/db";
import { sql } from "drizzle-orm";
import { Redis } from "ioredis";
import { listIncidents, getIncidentDetail, decideIncident, IncidentNotFoundError, InvalidDecisionStateError } from "./incidents.js";

const REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";

export function buildApp(): FastifyInstance {
  const app = Fastify({ logger: true });

  const redis = new Redis(REDIS_URL, {
    maxRetriesPerRequest: 1,
    lazyConnect: true,
  });

  app.get("/health", async () => {
    const db = await checkDb();
    const redisOk = await checkRedis(redis);
    return { db, redis: redisOk };
  });

  // List incidents, most severe first — the triage queue view.
  app.get("/incidents", async () => {
    const items = await listIncidents();
    return { incidents: items };
  });

  // One incident with its alerts, events, verdict, and full ledger trail.
  app.get<{ Params: { id: string } }>("/incidents/:id", async (req, reply) => {
    try {
      return await getIncidentDetail(req.params.id);
    } catch (err) {
      if (err instanceof IncidentNotFoundError) {
        return reply.code(404).send({ error: "incident_not_found", id: req.params.id });
      }
      throw err;
    }
  });

  // Human gate: approve or reject the agent's recommended action. Valid only
  // from `triaged`; a second decision or an un-triaged incident is a 409.
  for (const decision of ["approve", "reject"] as const) {
    const target = decision === "approve" ? "approved" : "rejected";
    app.post<{ Params: { id: string }; Body?: { decidedBy?: string; note?: string } }>(
      `/incidents/:id/${decision}`,
      async (req, reply) => {
        const decidedBy = req.body?.decidedBy ?? "operator";
        try {
          const result = await decideIncident(req.params.id, target, decidedBy, req.body?.note);
          return result;
        } catch (err) {
          if (err instanceof IncidentNotFoundError) {
            return reply.code(404).send({ error: "incident_not_found", id: req.params.id });
          }
          if (err instanceof InvalidDecisionStateError) {
            return reply
              .code(409)
              .send({ error: "invalid_decision_state", status: err.currentStatus });
          }
          throw err;
        }
      },
    );
  }

  app.addHook("onClose", async () => {
    redis.disconnect();
    await closeDb();
  });

  return app;
}

async function checkDb(): Promise<boolean> {
  try {
    await getDb().execute(sql`select 1`);
    return true;
  } catch {
    return false;
  }
}

async function checkRedis(redis: Redis): Promise<boolean> {
  try {
    if (redis.status !== "ready") {
      await redis.connect();
    }
    const pong = await redis.ping();
    return pong === "PONG";
  } catch {
    return false;
  }
}
