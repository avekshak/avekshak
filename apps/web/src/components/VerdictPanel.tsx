import type { Incident } from "@avekshak/schema";
import { VerdictBadge } from "./SeverityBadge.js";

/**
 * The agent's conclusion: verdict + confidence, with the rationale and the
 * recommended action it would take. Null verdict means the incident hasn't been
 * triaged yet.
 */
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
          <dd>{verdict.confidence}%</dd>
          <dt>Rationale</dt>
          <dd>{verdict.rationale}</dd>
          <dt>Recommended action</dt>
          <dd>{verdict.recommendedAction}</dd>
        </dl>
      )}
    </section>
  );
}
