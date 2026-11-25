import { useEffect, useState } from "react";
import type { IncidentDetail as Detail } from "../types.js";
import { getIncident, ApiError } from "../api.js";
import { SeverityBadge, StatusBadge } from "./SeverityBadge.js";
import { VerdictPanel } from "./VerdictPanel.js";
import { AlertsList } from "./AlertsList.js";
import { EventsList } from "./EventsList.js";
import { LedgerTimeline } from "./LedgerTimeline.js";
import { DecisionControls } from "./DecisionControls.js";

export function IncidentDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const [incident, setIncident] = useState<Detail | null>(null);
  const [status, setStatus] = useState<"loading" | "ok" | "notfound" | "error">("loading");
  const [errorMsg, setErrorMsg] = useState<string>("");

  function load() {
    setStatus("loading");
    getIncident(id)
      .then((d) => { setIncident(d); setStatus("ok"); })
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
      {/* Back navigation */}
      <div className="page-title-block" style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <button className="link-btn" onClick={onBack} aria-label="Back to incident list">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><polyline points="15 18 9 12 15 6"/></svg>
          Back to Console
        </button>
      </div>

      {status === "loading" && (
        <p className="loading" aria-live="polite">// Loading incident data…</p>
      )}
      {status === "notfound" && (
        <div className="notice notice-warn" role="alert">Incident not found: {id}</div>
      )}
      {status === "error" && (
        <div className="notice notice-error" role="alert">{errorMsg}</div>
      )}

      {status === "ok" && incident && (
        <>
          <div className="detail-header">
            <h2>{incident.title}</h2>
            <SeverityBadge severity={incident.severity} />
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
