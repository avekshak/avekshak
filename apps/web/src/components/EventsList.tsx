import type { NormalizedEvent } from "@avekshak/schema";

/** The raw normalized events behind this incident's alerts. */
export function EventsList({ events }: { events: NormalizedEvent[] }) {
  return (
    <section className="panel">
      <h2>Events ({events.length})</h2>
      {events.length === 0 ? (
        <p className="muted">No linked events.</p>
      ) : (
        <table className="sub-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Action</th>
              <th>Outcome</th>
              <th>Actor</th>
              <th>Target</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td className="muted">{new Date(e.ts).toLocaleString()}</td>
                <td>{e.source}</td>
                <td>{e.action}</td>
                <td>{e.outcome}</td>
                <td>{e.actor.user ?? e.actor.ip ?? "—"}</td>
                <td>{e.target.host ?? e.target.resource ?? e.target.ip ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
