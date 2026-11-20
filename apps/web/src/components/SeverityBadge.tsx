import type { Incident, Verdict } from "@avekshak/schema";

type BadgeColor = "red" | "amber" | "green" | "grey";

/** Map a 0–100 severity to a colour band. */
function severityColor(severity: number): BadgeColor {
  if (severity >= 70) return "red";
  if (severity >= 40) return "amber";
  if (severity > 0) return "green";
  return "grey";
}

/** Map a verdict to a colour: critical→red, suspicious→amber, benign→green. */
function verdictColor(verdict: Verdict["verdict"]): BadgeColor {
  if (verdict === "critical") return "red";
  if (verdict === "suspicious") return "amber";
  return "green";
}

export function SeverityBadge({ severity }: { severity: number }) {
  return <span className={`badge badge-${severityColor(severity)}`}>{severity}</span>;
}

export function VerdictBadge({ verdict }: { verdict: Incident["verdict"] }) {
  if (!verdict) return <span className="badge badge-grey">untriaged</span>;
  return (
    <span className={`badge badge-${verdictColor(verdict.verdict)}`}>{verdict.verdict}</span>
  );
}

export function StatusBadge({ status }: { status: Incident["status"] }) {
  const color: BadgeColor =
    status === "approved" ? "green" : status === "rejected" ? "red" : "grey";
  return <span className={`badge badge-${color}`}>{status}</span>;
}
