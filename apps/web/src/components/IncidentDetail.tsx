import { useEffect, useState } from "react";
import type { IncidentDetail as Detail } from "../types.js";
import { getIncident, ApiError } from "../api.js";
import { StatusBadge } from "./SeverityBadge.js";
import { VerdictPanel } from "./VerdictPanel.js";
import { AlertsList } from "./AlertsList.js";
import { EventsList } from "./EventsList.js";
import { LedgerTimeline } from "./LedgerTimeline.js";
import { DecisionControls } from "./DecisionControls.js";

/**
 * One incident, in full: header, the AI verdict, the correlated alerts and
 * their events, the ledger trail, and the approve/reject gate. The fetched
 * incident is held in state so the decision controls can mutate it in place and
 * resync after a server decision.
 */
export function IncidentDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const [incident, setIncident] = useState<Detail | null>(null);
  const [status, setStatus] = useState<"loading" | "ok" | "notfound" | "error">("loading");
  const [errorMsg, setErrorMsg] = useState<string>("");

  function load() {
    setStatus("loading");
    getIncident(id)
      .then((d) => {
        setIncident(d);
        setStatus("ok");
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError && err.status === 404) {
          setStatus("notfound");
        } else {
          setErrorMsg(err instanceof ApiError ? err.message : "failed to load incident");
          setStatus("error");
        }
      });
  }

  useEffect(load, [id]);

  return (
    <div>
      <button className="link-btn" onClick={onBack}>
        ← Back to incidents
      </button>

      {status === "loading" && <p className="loading">Loading incident…</p>}
      {status === "notfound" && <p className="notice notice-warn">Incident not found: {id}</p>}
      {status === "error" && <p className="notice notice-error">{errorMsg}</p>}

      {status === "ok" && incident && (
        <>
          <div className="detail-header">
            <h2>{incident.title}</h2>
            <StatusBadge status={incident.status} />
          </div>

          <DecisionControls incident={incident} onDecided={setIncident} onNeedsReload={load} />

          <VerdictPanel verdict={incident.verdict} />
          <AlertsList alerts={incident.alerts} />
          <EventsList events={incident.events} />
          <LedgerTimeline ledger={incident.ledger} />
        </>
      )}
    </div>
  );
}
