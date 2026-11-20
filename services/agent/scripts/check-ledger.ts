import { randomUUID } from "node:crypto";
import {
  getDb,
  incidents,
  ledger,
  closeDb,
  appendLedger,
  readLedger,
  nextSeq,
  ledgerCount,
} from "@avekshak/db";
import { sql, eq } from "drizzle-orm";

/**
 * Integration check for 4.2: the ledger is append-only and ordered. We create a
 * throwaway incident, append several entries, and assert (a) seq is a dense
 * monotonic sequence starting at 0, (b) readLedger returns them in order, and
 * (c) a double-write at an already-used seq is rejected by the unique constraint
 * — i.e. entries cannot be silently overwritten.
 */

async function main() {
  const db = getDb();
  const incidentId = randomUUID();

  // Clean any prior run, then seed a real incident (ledger FKs to incidents).
  await db.execute(sql`delete from ${ledger} where incident_id = ${incidentId}`);
  await db.execute(sql`delete from ${incidents} where id = ${incidentId}`);
  await db.insert(incidents).values({
    id: incidentId,
    title: "Ledger test incident",
    status: "open",
    severity: 40,
    correlationKey: `ledger-test:${incidentId}`,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  // Append an ordered investigation trail.
  const e0 = await appendLedger(incidentId, "system", "incident.opened", {
    correlationKey: `ledger-test:${incidentId}`,
  });
  const e1 = await appendLedger(incidentId, "agent", "triage.context_gathered", {
    alertCount: 3,
    eventCount: 3,
  });
  const e2 = await appendLedger(incidentId, "agent", "triage.verdict", {
    verdict: "critical",
    confidence: 91,
  });
  const e3 = await appendLedger(incidentId, "system", "incident.status_changed", {
    from: "open",
    to: "triaged",
  });

  const entries = await readLedger(incidentId);
  const seqs = entries.map((e) => e.seq);
  const actions = entries.map((e) => e.action);
  const count = await ledgerCount(incidentId);

  console.log("ledger seqs:", seqs.join(","));
  console.log("ledger actions:", actions.join(" → "));
  console.log("count:", count);

  // --- Append-only: a manual insert at an already-used seq must be rejected. ---
  let overwriteRejected = false;
  try {
    await db.insert(ledger).values({
      id: randomUUID(),
      incidentId,
      seq: 0, // already taken by e0
      ts: new Date(),
      actor: "human",
      action: "malicious.overwrite_attempt",
      detail: {},
    });
  } catch (err) {
    overwriteRejected = (err as { code?: string }).code === "23505";
  }

  // nextSeq keeps advancing (append-only — never reuses a slot).
  const afterSeq = await nextSeq(incidentId);

  console.log("overwrite at used seq rejected:", overwriteRejected);
  console.log("nextSeq after 4 entries:", afterSeq);

  // The original entries are untouched (no update/delete path exists).
  const stillFour = await ledgerCount(incidentId);

  // Cleanup.
  await db.execute(sql`delete from ${ledger} where incident_id = ${incidentId}`);
  await db.execute(sql`delete from ${incidents} where id = ${incidentId}`);
  await closeDb();

  const pass =
    seqs.join(",") === "0,1,2,3" &&
    actions[0] === "incident.opened" &&
    actions[3] === "incident.status_changed" &&
    entries[0].id === e0.id &&
    entries[2].id === e2.id &&
    e1.seq === 1 &&
    e3.seq === 3 &&
    count === 4 &&
    overwriteRejected &&
    afterSeq === 4 &&
    stillFour === 4;

  console.log(
    pass
      ? "PASS: ledger is ordered and append-only (overwrites rejected)"
      : "FAIL",
  );
  process.exit(pass ? 0 : 1);
}

main().catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
