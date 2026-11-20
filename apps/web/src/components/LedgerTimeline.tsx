import type { LedgerEntry } from "@avekshak/schema";

/**
 * The investigation ledger — the agent's (and human's) work, in append-only seq
 * order. This is the auditable trail: every context-gather, score, verdict, and
 * decision, with its JSON detail.
 */
export function LedgerTimeline({ ledger }: { ledger: LedgerEntry[] }) {
  const ordered = [...ledger].sort((a, b) => a.seq - b.seq);
  return (
    <section className="panel">
      <h2>Investigation Ledger ({ordered.length})</h2>
      {ordered.length === 0 ? (
        <p className="muted">No ledger entries.</p>
      ) : (
        <ol className="ledger">
          {ordered.map((entry) => (
            <li key={entry.id} className="ledger-entry">
              <span className="ledger-seq">#{entry.seq}</span>
              <span>
                <span className="ledger-action">{entry.action}</span>
                <div className="ledger-meta">
                  {entry.actor} · {new Date(entry.ts).toLocaleString()}
                </div>
              </span>
              <pre className="ledger-detail">{JSON.stringify(entry.detail, null, 2)}</pre>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
