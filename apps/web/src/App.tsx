import { useState } from "react";
import { IncidentList } from "./components/IncidentList.js";
import { IncidentDetail } from "./components/IncidentDetail.js";

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

      </header>

      {view.kind === "list" ? (
        <>
          <div className="page-title-block">
            <h1>Incident Console</h1>
          </div>
          <IncidentList onOpen={(id) => setView({ kind: "detail", id })} />
        </>
      ) : (
        <IncidentDetail id={view.id} onBack={() => setView({ kind: "list" })} />
      )}
    </main>
  );
}
