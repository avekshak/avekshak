import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";

const POSTGRES_URL =
  process.env.POSTGRES_URL ??
  "postgres://avekshak:avekshak@localhost:5432/avekshak";

async function main() {
  const client = postgres(POSTGRES_URL, { max: 1, onnotice: () => {} });
  const db = drizzle(client);
  await migrate(db, { migrationsFolder: "./migrations" });
  await client.end();
  console.log("migrations applied");
}

main().catch((err) => {
  console.error("migration failed:", err);
  process.exit(1);
});
