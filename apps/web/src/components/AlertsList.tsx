import type { Alert } from "@avekshak/schema";

/** The alerts correlated into this incident. */
export function AlertsList({ alerts }: { alerts: Alert[] }) {
  return (
    <section className="panel">
      <h2>Alerts ({alerts.length})</h2>
      {alerts.length === 0 ? (
        <p className="muted">No linked alerts.</p>
      ) : (
        <table className="sub-table">
          <thead>
            <tr>
              <th>Sev</th>
              <th>Title</th>
              <th>Rule</th>
              <th>Actor IP</th>
              <th>Target</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <td>{a.severity}</td>
                <td>{a.title}</td>
                <td className="muted">{a.ruleId}</td>
                <td>{a.actorIp ?? "—"}</td>
                <td>{a.targetHost ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
