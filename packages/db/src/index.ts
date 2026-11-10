import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema.js";

export * from "./schema.js";
export * from "./ledger.js";

const POSTGRES_URL =
  process.env.POSTGRES_URL ??
  "postgres://avekshak:avekshak@localhost:5432/avekshak";

let client: ReturnType<typeof postgres> | null = null;

export function getDb() {
  if (!client) {
    client = postgres(POSTGRES_URL);
  }
  return drizzle(client, { schema });
}

export async function closeDb(): Promise<void> {
  if (client) {
    await client.end();
    client = null;
  }
}
