import { randomUUID } from "node:crypto";
import { sql, eq, desc } from "drizzle-orm";
import type { LedgerEntry } from "@avekshak/schema";
import { getDb } from "./index.js";
import { ledger } from "./schema.js";

/** Who/what produced a ledger entry. */
export type LedgerActor = "agent" | "system" | "human";

/**
 * The investigation ledger is append-only: every step of an incident's handling
 * (context gathered, model verdict, status change, human decision) is recorded
 * as an immutable, ordered row. Ordering is a monotonic per-incident `seq`,
 * backed by a unique(incidentId, seq) constraint so a gap or a double-write is a
 * hard error, never a silent overwrite. Nothing here updates or deletes.
 */

/** Next sequence number for an incident (0 for the first entry). */
export async function nextSeq(incidentId: string): Promise<number> {
  const rows = await getDb()
    .select({ seq: ledger.seq })
    .from(ledger)
    .where(eq(ledger.incidentId, incidentId))
    .orderBy(desc(ledger.seq))
    .limit(1);
  return rows.length === 0 ? 0 : rows[0].seq + 1;
}

/**
 * Append one entry. Computes the next seq and inserts; if a concurrent writer
 * grabbed that seq first (unique-constraint violation) we recompute and retry a
 * bounded number of times. Returns the persisted entry.
 */
export async function appendLedger(
  incidentId: string,
  actor: LedgerActor,
  action: string,
  detail: Record<string, unknown>,
  maxRetries = 5,
): Promise<LedgerEntry> {
  const db = getDb();
  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    const seq = await nextSeq(incidentId);
    const id = randomUUID();
    const ts = new Date();
    try {
      await db.insert(ledger).values({ id, incidentId, seq, ts, actor, action, detail });
      return {
        id,
        incidentId,
        seq,
        ts: ts.toISOString(),
        actor,
        action,
        detail,
      };
    } catch (err) {
      // 23505 = unique_violation: someone took this seq; recompute and retry.
      const code = (err as { code?: string }).code;
      if (code === "23505" && attempt < maxRetries) continue;
      throw err;
    }
  }
  throw new Error(
    `appendLedger: could not obtain a free seq for incident ${incidentId} after ${maxRetries} retries`,
  );
}

/** Read an incident's ledger in order (oldest first). For checks and the API. */
export async function readLedger(incidentId: string): Promise<LedgerEntry[]> {
  const rows = await getDb()
    .select()
    .from(ledger)
    .where(eq(ledger.incidentId, incidentId))
    .orderBy(ledger.seq);
  return rows.map((r) => ({
    id: r.id,
    incidentId: r.incidentId,
    seq: r.seq,
    ts: (r.ts as Date).toISOString(),
    actor: r.actor as LedgerActor,
    action: r.action,
    detail: r.detail as Record<string, unknown>,
  }));
}

/** Count entries for an incident (cheap assertion helper). */
export async function ledgerCount(incidentId: string): Promise<number> {
  const rows = (await getDb().execute(
    sql`select count(*)::int as n from ${ledger} where incident_id = ${incidentId}`,
  )) as unknown as Array<{ n: number }>;
  return rows[0].n;
}
