import { useCallback, useEffect, useRef, useState } from "react";
import { listAlerts, listEvents, ApiError } from "../api.js";
import type { RawAlert, RawEvent } from "../api.js";

const POLL_INTERVAL_MS = 5_000;

type Tab = "alerts" | "events";

function severityColor(s: number): string {
  if (s >= 70) return "var(--red)";
  if (s >= 40) return "var(--amber)";
  if (s > 0)   return "var(--green)";
  return "var(--grey)";
}

function timeStamp(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  });
}

/* ---------- Alert row ---------- */
function AlertRow({ a }: { a: RawAlert }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="log-row">
      <div className="log-row-header" onClick={() => setOpen((p) => !p)}>
        <span className="log-sev-dot" style={{ background: severityColor(a.severity) }} />
        <span className="log-ts">{timeStamp(a.ts)}</span>
        <span className="log-title">{a.title}</span>
        <span className="log-meta">{a.ruleId}</span>
        {a.actorIp   && <span className="log-pill">{a.actorIp}</span>}
        {a.actorUser && <span className="log-pill">{a.actorUser}</span>}
        {a.targetHost && <span className="log-pill">{a.targetHost}</span>}
        <span className="log-chevron">{open ? "▲" : "▼"}</span>
      </div>
      {open && (
        <pre className="log-raw">{JSON.stringify(a, null, 2)}</pre>
      )}
    </div>
  );
}

/* ---------- Event row ---------- */
function EventRow({ e }: { e: RawEvent }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="log-row">
      <div className="log-row-header" onClick={() => setOpen((p) => !p)}>
        <span className="log-sev-dot" style={{ background: severityColor(e.severity) }} />
        <span className="log-ts">{timeStamp(e.ts)}</span>
        <span className="log-pill log-pill--source">{e.source}</span>
        <span className="log-title">{e.action}</span>
        <span className="log-meta">{e.category}</span>
        {e.actor?.ip   && <span className="log-pill">{e.actor.ip}</span>}
        {e.actor?.user && <span className="log-pill">{e.actor.user}</span>}
        {e.target?.host && <span className="log-pill">{e.target.host}</span>}
        <span className="log-chevron">{open ? "▲" : "▼"}</span>
      </div>
      {open && (
        <pre className="log-raw">{JSON.stringify(e, null, 2)}</pre>
      )}
    </div>
  );
}

/* ---------- Main drawer ---------- */
export function RawLogsDrawer({ onClose }: { onClose: () => void }) {
  const [tab, setTab]       = useState<Tab>("alerts");
  const [alerts, setAlerts] = useState<RawAlert[] | null>(null);
  const [events, setEvents] = useState<RawEvent[] | null>(null);
  const [error, setError]   = useState<string | null>(null);
  const drawerRef           = useRef<HTMLDivElement>(null);
  const intervalRef         = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchLogs = useCallback(async () => {
    try {
      const [a, e] = await Promise.all([listAlerts(), listEvents()]);
      setAlerts(a);
      setEvents(e);
      setError(null);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "failed to load logs");
    }
  }, []);

  useEffect(() => {
    fetchLogs();
    intervalRef.current = setInterval(fetchLogs, POLL_INTERVAL_MS);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [fetchLogs]);

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  // Close on backdrop click
  const onBackdrop = (e: React.MouseEvent) => {
    if (drawerRef.current && !drawerRef.current.contains(e.target as Node)) onClose();
  };

  const rows = tab === "alerts" ? alerts : events;

  return (
    <div className="drawer-backdrop" onClick={onBackdrop} role="dialog" aria-modal="true" aria-label="Raw logs">
      <div className="drawer" ref={drawerRef}>
        {/* Header */}
        <div className="drawer-header">
          <div className="drawer-title-block">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2" aria-hidden="true"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
            <span className="drawer-title">Raw Logs</span>
          </div>
          <button className="drawer-close" onClick={onClose} aria-label="Close">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>

        {/* Tabs */}
        <div className="drawer-tabs">
          <button
            className={`drawer-tab${tab === "alerts" ? " drawer-tab--active" : ""}`}
            onClick={() => setTab("alerts")}
          >
            Alerts
            {alerts && <span className="drawer-tab-count">{alerts.length}</span>}
          </button>
          <button
            className={`drawer-tab${tab === "events" ? " drawer-tab--active" : ""}`}
            onClick={() => setTab("events")}
          >
            Events
            {events && <span className="drawer-tab-count">{events.length}</span>}
          </button>
        </div>

        {/* Body */}
        <div className="drawer-body">
          {error && <div className="notice notice-error">{error}</div>}

          {!error && rows === null && (
            <div className="drawer-loading">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="skeleton-pulse" style={{ height: 36, borderRadius: 6 }} />
              ))}
            </div>
          )}

          {!error && rows !== null && rows.length === 0 && (
            <div className="drawer-empty">No {tab} yet.</div>
          )}

          {!error && rows !== null && rows.length > 0 && (
            <div className="log-list">
              {tab === "alerts"
                ? (alerts as RawAlert[]).map((a) => <AlertRow key={a.id} a={a} />)
                : (events as RawEvent[]).map((e) => <EventRow key={e.id} e={e} />)
              }
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
