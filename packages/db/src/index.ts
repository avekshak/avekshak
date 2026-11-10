import postgres from "postgres";
import { drizzle } from "drizzle-orm/postgres-js";
import * as schema from "./schema.js";

export * from "./schema.js";

export function createDb(connectionString?: string) {
  const url = connectionString ?? process.env.POSTGRES_URL ?? "postgres://avekshak:avekshak@localhost:5433/avekshak";
  const client = postgres(url, { max: 10 });
  return drizzle(client, { schema });
}

export type Db = ReturnType<typeof createDb>;
