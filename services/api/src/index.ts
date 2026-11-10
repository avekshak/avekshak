import Fastify from "fastify";
import { createDb } from "@avekshak/db";
import { Redis } from "ioredis";

const PORT = Number(process.env.API_PORT ?? 8000);
const REDIS_URL = process.env.REDIS_URL ?? "redis://localhost:6379";

const app = Fastify({ logger: true });

const db = createDb();
const redis = new Redis(REDIS_URL, { maxRetriesPerRequest: 1, lazyConnect: true });

app.get("/health", async (_req, reply) => {
  let dbOk = false;
  let redisOk = false;

  try {
    await db.$client.unsafe("SELECT 1");
    dbOk = true;
  } catch {
    // db unreachable
  }

  try {
    await redis.ping();
    redisOk = true;
  } catch {
    // redis unreachable
  }

  const status = dbOk && redisOk ? 200 : 503;
  return reply.status(status).send({ db: dbOk, redis: redisOk });
});

app.listen({ port: PORT, host: "0.0.0.0" }, (err) => {
  if (err) {
    app.log.error(err);
    process.exit(1);
  }
});
