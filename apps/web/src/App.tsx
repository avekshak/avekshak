import { useState } from "react";
import { IncidentList } from "./components/IncidentList.js";
import { IncidentDetail } from "./components/IncidentDetail.js";

// Hand-rolled routing: the console only has two screens, so a tagged-union in
// state is simpler than pulling in react-router. list → detail → back.
type View = { kind: "list" } | { kind: "detail"; id: string };

export function App() {
  const [view, setView] = useState<View>({ kind: "list" });

  return (
    <main className="app">
      <header className="app-header">
        <h1>Avekshak</h1>
        <span className="app-subtitle">Incident Console</span>
      </header>

      {view.kind === "list" ? (
        <IncidentList onOpen={(id) => setView({ kind: "detail", id })} />
      ) : (
        <IncidentDetail id={view.id} onBack={() => setView({ kind: "list" })} />
      )}
    </main>
  );
}
