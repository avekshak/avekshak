import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Incident } from "@avekshak/schema";
import { listIncidents, ApiError } from "../api.js";
import { SeverityBadge, VerdictBadge, StatusBadge } from "./SeverityBadge.js";

const POLL_INTERVAL_MS = 5_000; // 5 s

type SortDir = "desc" | "asc";
type VerdictFilter = "all" | "critical" | "suspicious" | "benign" | "untriaged";
type StatusFilter  = "all" | "open" | "triaged" | "approved" | "rejected" | "closed";

/* ---------- Polling hook ---------- */

function usePolledIncidents() {
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [error, setError]         = useState<string | null>(null);
  const [lastFetched, setLastFetched] = useState<Date | null>(null);
  const [fresh, setFresh]         = useState(false);
  const [, setTick]               = useState(0);
  const intervalRef               = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetch_ = useCallback(async (isFirst: boolean) => {
    try {
      const rows = await listIncidents();
      setIncidents(rows);
      setError(null);
      setLastFetched(new Date());
      if (!isFirst) {
        setFresh(true);
        setTimeout(() => setFresh(false), 1200);
      }
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "failed to load incidents");
    }
  }, []);

  useEffect(() => {
    fetch_(true);
    intervalRef.current = setInterval(() => fetch_(false), POLL_INTERVAL_MS);
    const tickRef = setInterval(() => setTick((n) => n + 1), 30_000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      clearInterval(tickRef);
    };
  }, [fetch_]);

  return { incidents, error, lastFetched, fresh };
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

/* ---------- Severity distribution bar ---------- */

function SeverityBar({ incidents }: { incidents: Incident[] }) {
  const total = incidents.length;
  if (total === 0) return null;

  const bands = [
    { label: "Critical", min: 70,  max: 101, color: "var(--red)"   },
    { label: "High",     min: 40,  max: 70,  color: "var(--amber)" },
    { label: "Low",      min: 1,   max: 40,  color: "var(--green)" },
    { label: "Info",     min: 0,   max: 1,   color: "var(--grey)"  },
  ];

  const counts = bands.map((b) => ({
    ...b,
    count: incidents.filter((i) => i.severity >= b.min && i.severity < b.max).length,
  }));

  return (
    <div className="chart-card">
      <p className="chart-title">Severity Distribution</p>
      {/* Stacked bar */}
      <div className="sev-bar-track" role="img" aria-label="Severity distribution bar">
        {counts.map((b) =>
          b.count > 0 ? (
            <div
              key={b.label}
              className="sev-bar-segment"
              style={{ flex: b.count, background: b.color }}
              title={`${b.label}: ${b.count}`}
            />
          ) : null
        )}
      </div>
      {/* Legend */}
      <div className="sev-bar-legend">
        {counts.map((b) => (
          <span key={b.label} className="sev-bar-legend-item">
            <span className="sev-bar-dot" style={{ background: b.color }} />
            <span className="sev-bar-band-label">{b.label}</span>
            <span className="sev-bar-band-count">{b.count}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/* ---------- Verdict donut ---------- */

function VerdictDonut({ incidents }: { incidents: Incident[] }) {
  const total = incidents.length;
  if (total === 0) return null;

  const slices = [
    { label: "Critical",   color: "var(--red)",   count: incidents.filter((i) => i.verdict?.verdict === "critical").length   },
    { label: "Suspicious", color: "var(--amber)",  count: incidents.filter((i) => i.verdict?.verdict === "suspicious").length },
    { label: "Benign",     color: "var(--green)",  count: incidents.filter((i) => i.verdict?.verdict === "benign").length    },
    { label: "Untriaged",  color: "var(--grey)",   count: incidents.filter((i) => i.verdict === null).length                 },
  ].filter((s) => s.count > 0);

  /* Build SVG arc paths */
  const R = 36; const cx = 48; const cy = 48; const stroke = 10;
  const circumference = 2 * Math.PI * R;

  let offset = 0;
  const arcs = slices.map((s) => {
    const frac = s.count / total;
    const dash = frac * circumference;
    const arc = { ...s, dash, offset, frac };
    offset += dash;
    return arc;
  });

  return (
    <div className="chart-card">
      <p className="chart-title">Verdict Breakdown</p>
      <div className="donut-wrap">
        <svg width="96" height="96" viewBox="0 0 96 96" aria-hidden="true">
          {/* track */}
          <circle cx={cx} cy={cy} r={R} fill="none" stroke="var(--border)" strokeWidth={stroke} />
          {arcs.map((a) => (
            <circle
              key={a.label}
              cx={cx} cy={cy} r={R}
              fill="none"
              stroke={a.color}
              strokeWidth={stroke}
              strokeDasharray={`${a.dash} ${circumference - a.dash}`}
              strokeDashoffset={-a.offset + circumference / 4}
              strokeLinecap="butt"
            />
          ))}
          {/* centre label */}
          <text x={cx} y={cy - 4} textAnchor="middle" fontSize="14" fontWeight="700" fill="var(--text)" fontFamily="'JetBrains Mono',monospace">{total}</text>
          <text x={cx} y={cy + 10} textAnchor="middle" fontSize="8" fill="var(--muted)" fontFamily="'JetBrains Mono',monospace">TOTAL</text>
        </svg>
        <div className="donut-legend">
          {slices.map((s) => (
            <span key={s.label} className="donut-legend-item">
              <span className="sev-bar-dot" style={{ background: s.color }} />
              <span className="sev-bar-band-label">{s.label}</span>
              <span className="sev-bar-band-count">{s.count}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ---------- KPI bar ---------- */

const kpiIcons: Record<string, JSX.Element> = {
  total: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="9" y1="9" x2="15" y2="9"/><line x1="9" y1="12" x2="15" y2="12"/><line x1="9" y1="15" x2="12" y2="15"/></svg>
  ),
  critical: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
  ),
  triaged: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
  ),
  approved: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
  ),
  avgSev: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
  ),
  open: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
  ),
  rejected: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
  ),
};

function KpiBar({ incidents }: { incidents: Incident[] }) {
  const total = incidents.length;
  const critical = incidents.filter((i) => i.severity >= 70).length;
  const open = incidents.filter((i) => i.status === "open").length;
  const approved = incidents.filter((i) => i.status === "approved").length;
  const rejected = incidents.filter((i) => i.status === "rejected").length;
  const avgSev =
    total > 0
      ? Math.round(incidents.reduce((s, i) => s + i.severity, 0) / total)
      : 0;

  const kpis: { key: string; label: string; value: string | number; accent?: string }[] = [
    { key: "total",    label: "Total Incidents", value: total },
    { key: "critical", label: "Critical",        value: critical,  accent: "red" },
    { key: "open",     label: "Open",            value: open,      accent: "amber" },
    { key: "approved", label: "Approved",        value: approved,  accent: "green" },
    { key: "rejected", label: "Rejected",        value: rejected },
    { key: "avgSev",   label: "Avg Severity",    value: avgSev,    accent: "cyan" },
  ];

  return (
    <div className="kpi-bar" role="region" aria-label="Incident KPI metrics">
      {kpis.map((k) => (
        <div
          key={k.key}
          className={`kpi-card${k.accent ? ` kpi-card--${k.accent}` : ""}`}
        >
          <span className="kpi-icon">{kpiIcons[k.key]}</span>
          <span className="kpi-value">{k.value}</span>
          <span className="kpi-label">{k.label}</span>
        </div>
      ))}
    </div>
  );
}

/* ---------- Toolbar: sort + filter dropdowns ---------- */

function Toolbar({
  total,
  sortDir,
  onSort,
  verdictFilter,
  onVerdictFilter,
  statusFilter,
  onStatusFilter,
  lastFetched,
  fresh,
}: {
  total: number;
  sortDir: SortDir;
  onSort: (d: SortDir) => void;
  verdictFilter: VerdictFilter;
  onVerdictFilter: (v: VerdictFilter) => void;
  statusFilter: StatusFilter;
  onStatusFilter: (s: StatusFilter) => void;
  lastFetched: Date | null;
  fresh: boolean;
}) {
  const hasActiveFilter = verdictFilter !== "all" || statusFilter !== "all";

  return (
    <div className="list-toolbar">
      <div className="list-toolbar-left">
        <p className="list-count">
          <span className="list-count-num">{total}</span>{" "}
          {total === 1 ? "incident" : "incidents"} in queue
        </p>
        {lastFetched && (
          <span className={`poll-indicator${fresh ? " poll-indicator--fresh" : ""}`}>
            <span className="poll-dot" />
            updated {timeAgo(lastFetched.toISOString())}
          </span>
        )}
      </div>

      <div className="toolbar-controls">
        {/* Verdict filter */}
        <label className="filter-label" htmlFor="filter-verdict">
          Verdict
          <select
            id="filter-verdict"
            className={`filter-select${verdictFilter !== "all" ? " filter-select--active" : ""}`}
            value={verdictFilter}
            onChange={(e) => onVerdictFilter(e.target.value as VerdictFilter)}
          >
            <option value="all">All verdicts</option>
            <option value="critical">Critical</option>
            <option value="suspicious">Suspicious</option>
            <option value="benign">Benign</option>
            <option value="untriaged">Untriaged</option>
          </select>
        </label>

        {/* Status filter */}
        <label className="filter-label" htmlFor="filter-status">
          Status
          <select
            id="filter-status"
            className={`filter-select${statusFilter !== "all" ? " filter-select--active" : ""}`}
            value={statusFilter}
            onChange={(e) => onStatusFilter(e.target.value as StatusFilter)}
          >
            <option value="all">All statuses</option>
            <option value="open">Open</option>
            <option value="triaged">Triaged</option>
            <option value="approved">Approved</option>
            <option value="rejected">Rejected</option>
            <option value="closed">Closed</option>
          </select>
        </label>

        {/* Sort */}
        <div className="sort-group">
          <span className="sort-group-label">Sort by severity</span>
          <div className="sort-group-btns">
            <button
              className={`sort-btn${sortDir === "desc" ? " sort-btn--active" : ""}`}
              onClick={() => onSort("desc")}
              aria-pressed={sortDir === "desc"}
            >
              ↓ Highest
            </button>
            <button
              className={`sort-btn${sortDir === "asc" ? " sort-btn--active" : ""}`}
              onClick={() => onSort("asc")}
              aria-pressed={sortDir === "asc"}
            >
              ↑ Lowest
            </button>
          </div>
        </div>

        {/* Clear filters */}
        {hasActiveFilter && (
          <button
            className="clear-filters-btn"
            onClick={() => { onVerdictFilter("all"); onStatusFilter("all"); }}
            aria-label="Clear all filters"
          >
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            Clear
          </button>
        )}
      </div>
    </div>
  );
}

/* ---------- Radial severity gauge (SVG arc) ---------- */

function RadialGauge({ severity, color }: { severity: number; color: string }) {
  const R = 22; const cx = 28; const cy = 28;
  const circumference = 2 * Math.PI * R;
  const filled = (severity / 100) * circumference;
  const colorVar =
    color === "red"   ? "var(--red)"   :
    color === "amber" ? "var(--amber)" :
    color === "green" ? "var(--green)" : "var(--grey)";

  return (
    <svg width="56" height="56" viewBox="0 0 56 56" aria-label={`Severity ${severity}`} role="img" flex-shrink="0" style={{ flexShrink: 0 }}>
      {/* track */}
      <circle cx={cx} cy={cy} r={R} fill="none" stroke="var(--border)" strokeWidth="4" />
      {/* filled arc — starts at top (rotate -90deg) */}
      <circle
        cx={cx} cy={cy} r={R}
        fill="none"
        stroke={colorVar}
        strokeWidth="4"
        strokeDasharray={`${filled} ${circumference - filled}`}
        strokeDashoffset={circumference / 4}
        strokeLinecap="round"
        style={{ filter: `drop-shadow(0 0 4px ${colorVar})` }}
      />
      {/* score */}
      <text x={cx} y={cy + 4} textAnchor="middle" fontSize="12" fontWeight="700" fill={colorVar} fontFamily="'JetBrains Mono',monospace">
        {severity}
      </text>
    </svg>
  );
}

/* ---------- Single incident card ---------- */

function IncidentCard({ incident, onOpen }: { incident: Incident; onOpen: (id: string) => void }) {
  const color =
    incident.severity >= 70 ? "red" :
    incident.severity >= 40 ? "amber" :
    incident.severity > 0   ? "green" : "grey";

  return (
    <article
      className={`incident-card incident-card--${color}`}
      onClick={() => onOpen(incident.id)}
      role="button"
      tabIndex={0}
      aria-label={`Open incident: ${incident.title}`}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onOpen(incident.id); }
      }}
    >
      {/* Header: radial gauge + title */}
      <div className="inc-card-header">
        <RadialGauge severity={incident.severity} color={color} />
        <div className="inc-card-title-block">
          <h3 className="inc-card-title">{incident.title}</h3>
          <p className="inc-card-id muted">
            #{incident.id.slice(0, 8)} · {incident.correlationKey}
          </p>
        </div>
      </div>

      {/* Badges */}
      <div className="inc-card-badges">
        <div className="inc-card-badge-group">
          <span className="inc-badge-label">Verdict</span>
          <VerdictBadge verdict={incident.verdict} />
        </div>
        <div className="inc-card-badge-group">
          <span className="inc-badge-label">Status</span>
          <StatusBadge status={incident.status} />
        </div>
        {incident.verdict && (
          <div className="inc-card-badge-group">
            <span className="inc-badge-label">Conf</span>
            <span className="badge badge-grey">{incident.verdict.confidence}%</span>
          </div>
        )}
        <div className="inc-card-badge-group" style={{ marginLeft: "auto" }}>
          <SeverityBadge severity={incident.severity} />
        </div>
      </div>

      {/* Rationale preview */}
      {incident.verdict && (
        <p className="inc-card-rationale">
          {incident.verdict.rationale.length > 130
            ? incident.verdict.rationale.slice(0, 130) + "…"
            : incident.verdict.rationale}
        </p>
      )}

      {/* Footer */}
      <div className="inc-card-footer">
        <div className="inc-card-time-pair">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          <span>Updated {timeAgo(incident.updatedAt)}</span>
        </div>
        <div className="inc-card-time-pair">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
          <span>{new Date(incident.createdAt).toLocaleDateString()}</span>
        </div>
      </div>
    </article>
  );
}

/* ---------- Main export ---------- */

export function IncidentList({ onOpen }: { onOpen: (id: string) => void }) {
  const { incidents, error, lastFetched, fresh } = usePolledIncidents();
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");

  const filtered = useMemo(() => {
    if (!incidents) return [];
    return incidents
      .filter((i) => {
        if (verdictFilter === "all") return true;
        if (verdictFilter === "untriaged") return i.verdict === null;
        return i.verdict !== null && i.verdict.verdict === verdictFilter;
      })
      .filter((i) => {
        if (statusFilter === "all") return true;
        return i.status === statusFilter;
      })
      .sort((a, b) =>
        sortDir === "desc" ? b.severity - a.severity : a.severity - b.severity,
      );
  }, [incidents, sortDir, verdictFilter, statusFilter]);

  if (error)
    return <div className="notice notice-error" role="alert">{error}</div>;

  if (incidents === null)
    return (
      <div className="skeleton-page" aria-busy="true" aria-label="Loading incidents">
        <div className="kpi-bar skeleton-kpi">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="kpi-card skeleton-pulse" style={{ height: 92 }} />
          ))}
        </div>
        <div className="incident-grid">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="incident-card skeleton-pulse" style={{ minHeight: 170 }} />
          ))}
        </div>
      </div>
    );

  if (incidents.length === 0)
    return (
      <div className="empty-state">
        <svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <h2>No incidents detected</h2>
        <p>
          Seed the demo data with{" "}
          <code>pnpm --filter @avekshak/web seed</code>
        </p>
      </div>
    );

  return (
    <div className="incident-list-page">
      {/* Section 1: KPI Metrics */}
      <section aria-labelledby="kpi-heading">
        <h2 id="kpi-heading" className="section-heading">Overview</h2>
        <KpiBar incidents={incidents} />
        <div className="charts-row">
          <SeverityBar incidents={incidents} />
          <VerdictDonut incidents={incidents} />
        </div>
      </section>

      {/* Section 2: Triage Queue */}
      <section aria-labelledby="queue-heading">
        <h2 id="queue-heading" className="section-heading">Triage Queue</h2>
        <Toolbar
          total={filtered.length}
          sortDir={sortDir}
          onSort={setSortDir}
          verdictFilter={verdictFilter}
          onVerdictFilter={setVerdictFilter}
          statusFilter={statusFilter}
          onStatusFilter={setStatusFilter}
          lastFetched={lastFetched}
          fresh={fresh}
        />
        {filtered.length === 0 ? (
          <div className="filter-empty">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <p>No incidents match the current filters.</p>
            <button className="clear-filters-btn" onClick={() => { setVerdictFilter("all"); setStatusFilter("all"); }}>
              Clear filters
            </button>
          </div>
        ) : (
          <div className="incident-grid">
            {filtered.map((inc) => (
              <IncidentCard key={inc.id} incident={inc} onOpen={onOpen} />
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
