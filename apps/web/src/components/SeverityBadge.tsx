import type { Incident, Verdict } from "@avekshak/schema";

type BadgeColor = "red" | "amber" | "green" | "grey";

function severityColor(severity: number): BadgeColor {
  if (severity >= 70) return "red";
  if (severity >= 40) return "amber";
  if (severity > 0) return "green";
  return "grey";
}

function verdictColor(verdict: Verdict["verdict"]): BadgeColor {
  if (verdict === "critical") return "red";
  if (verdict === "suspicious") return "amber";
  return "green";
}

export function SeverityBadge({ severity }: { severity: number }) {
  return (
    <span className={`badge badge-${severityColor(severity)}`}>
      {severity}
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict: Incident["verdict"] }) {
  if (!verdict) return <span className="badge badge-grey">untriaged</span>;
  return (
    <span className={`badge badge-${verdictColor(verdict.verdict)}`}>
      {verdict.verdict}
    </span>
  );
}

export function StatusBadge({ status }: { status: Incident["status"] }) {
  const color: BadgeColor =
    status === "approved" ? "green" :
    status === "rejected" ? "red" :
    status === "triaged"  ? "amber" : "grey";
  return <span className={`badge badge-${color}`}>{status}</span>;
}
