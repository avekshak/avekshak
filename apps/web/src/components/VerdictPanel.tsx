import type { Incident } from "@avekshak/schema";
import { VerdictBadge } from "./SeverityBadge.js";

function ConfidenceBar({ confidence, verdict }: { confidence: number; verdict: string }) {
  const color =
    verdict === "critical"   ? "var(--red)"   :
    verdict === "suspicious" ? "var(--amber)" : "var(--green)";

  return (
    <div className="conf-bar-wrap" aria-label={`Confidence ${confidence}%`}>
      <div className="conf-bar-track">
        <div
          className="conf-bar-fill"
          style={{ width: `${confidence}%`, background: color, boxShadow: `0 0 6px ${color}` }}
        />
      </div>
      <span className="conf-bar-label">{confidence}%</span>
    </div>
  );
}

export function VerdictPanel({ verdict }: { verdict: Incident["verdict"] }) {
  return (
    <section className="panel">
      <h2>AI Verdict</h2>
      {!verdict ? (
        <p className="muted">Not yet triaged.</p>
      ) : (
        <dl className="kv">
          <dt>Verdict</dt>
          <dd>
            <VerdictBadge verdict={verdict} />
          </dd>
          <dt>Confidence</dt>
          <dd>
            <ConfidenceBar confidence={verdict.confidence} verdict={verdict.verdict} />
          </dd>
          <dt>Rationale</dt>
          <dd>{verdict.rationale}</dd>
          <dt>Recommended action</dt>
          <dd>{verdict.recommendedAction}</dd>
        </dl>
      )}
    </section>
  );
}
