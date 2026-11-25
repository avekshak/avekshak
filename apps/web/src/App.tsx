import { useState } from "react";
import { IncidentList } from "./components/IncidentList.js";
import { IncidentDetail } from "./components/IncidentDetail.js";
import { EventsPage } from "./components/EventsPage.js";

type Tab = "incidents" | "events";
type View = { kind: "list" } | { kind: "detail"; id: string };

export function App() {
  const [tab, setTab] = useState<Tab>("incidents");
  const [view, setView] = useState<View>({ kind: "list" });

  function switchTab(next: Tab) {
    setTab(next);
    setView({ kind: "list" });
  }

  return (
    <main className="app">
      <header className="app-header">
        <h1>Avekshak</h1>
        <span className="app-subtitle">Incident Console</span>
        <nav className="app-tabs">
          <button
            className={`tab-btn${tab === "incidents" ? " tab-btn--active" : ""}`}
            onClick={() => switchTab("incidents")}
          >
            Incidents
          </button>
          <button
            className={`tab-btn${tab === "events" ? " tab-btn--active" : ""}`}
            onClick={() => switchTab("events")}
          >
            Events
          </button>
        </nav>
      </header>

      {tab === "events" ? (
        <EventsPage />
      ) : view.kind === "list" ? (
        <IncidentList onOpen={(id) => setView({ kind: "detail", id })} />
      ) : (
        <IncidentDetail id={view.id} onBack={() => setView({ kind: "list" })} />
      )}
    </main>
  );
}


