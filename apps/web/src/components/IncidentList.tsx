import { useEffect, useState } from "react";
import type { Incident } from "@avekshak/schema";
import { listIncidents, ApiError } from "../api.js";
import { SeverityBadge, VerdictBadge, StatusBadge } from "./SeverityBadge.js";

/**
 * The triage queue: every incident, most severe first (the API already sorts
 * severity DESC, updatedAt DESC, so we render in received order). Clicking a
 * row opens its detail.
 */
export function IncidentList({ onOpen }: { onOpen: (id: string) => void }) {
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const fetch = () =>
      listIncidents()
        .then((rows) => {
          if (!cancelled) setIncidents(rows);
        })
        .catch((err: unknown) => {
          if (!cancelled)
            setError(err instanceof ApiError ? err.message : "failed to load incidents");
        });
    fetch();
    const timer = setInterval(fetch, 5000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  if (error) return <p className="notice notice-error">{error}</p>;
  if (incidents === null) return <p className="loading">Loading incidents…</p>;
  if (incidents.length === 0)
    return (
      <p className="empty">
        No incidents yet. Seed the demo data with <code>pnpm --filter @avekshak/web seed</code>.
      </p>
    );

  return (
    <table className="incident-table">
      <thead>
        <tr>
          <th>Sev</th>
          <th>Incident</th>
          <th>Verdict</th>
          <th>Status</th>
          <th>Updated</th>
        </tr>
      </thead>
      <tbody>
        {incidents.map((inc) => (
          <tr key={inc.id} onClick={() => onOpen(inc.id)}>
            <td>
              <SeverityBadge severity={inc.severity} />
            </td>
            <td>{inc.title}</td>
            <td>
              <VerdictBadge verdict={inc.verdict} />
            </td>
            <td>
              <StatusBadge status={inc.status} />
            </td>
            <td className="muted">{new Date(inc.updatedAt).toLocaleString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
