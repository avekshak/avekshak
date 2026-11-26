import { useState } from "react";
import { IncidentList } from "./components/IncidentList.js";
import { IncidentDetail } from "./components/IncidentDetail.js";
import { RawLogsDrawer } from "./components/RawLogsDrawer.js";

type View = { kind: "list" } | { kind: "detail"; id: string };

/** Shield SVG icon for the logo */
function ShieldIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

export function App() {
  const [view, setView] = useState<View>({ kind: "list" });
  const [logsOpen, setLogsOpen] = useState(false);

  return (
    <main className="app">
      {/* Sticky top nav bar */}
      <header className="app-header" role="banner">
        <div className="app-logo">
          <div className="app-logo-icon" aria-hidden="true">
            <ShieldIcon />
          </div>
          <div className="app-logo-text">
            <span className="app-logo-name">Avekshak</span>
            <span className="app-logo-tagline">AI-SOC // v1.0</span>
          </div>
        </div>

        <div className="app-header-right">
        </div>
      </header>

      {view.kind === "list" ? (
        <>
          <div className="page-title-block">
            <h1>Incident Console</h1>
            <button
              className="logs-btn"
              onClick={() => setLogsOpen(true)}
              aria-label="Open raw logs"
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
              Raw Logs
            </button>
          </div>
          <IncidentList onOpen={(id) => setView({ kind: "detail", id })} />
        </>
      ) : (
        <IncidentDetail id={view.id} onBack={() => setView({ kind: "list" })} />
      )}

      {logsOpen && <RawLogsDrawer onClose={() => setLogsOpen(false)} />}
    </main>
  );
}

