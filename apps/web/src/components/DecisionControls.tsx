import { useState } from "react";
import type { IncidentDetail as Detail, ResponsePlan } from "../types.js";
import { approve, reject, ApiError } from "../api.js";

/**
 * The human gate. Approve/reject are enabled ONLY when the incident is
 * `triaged` — any other status means the decision was already made (or the
 * agent hasn't finished), so the buttons are disabled with a note.
 *
 * On click we optimistically flip the local status and disable while pending.
 * On success we apply the server's status and, for an approval, surface the
 * dry-run response plan. On an ApiError (e.g. a 409 because someone else decided
 * first) we ask the parent to reload so the view rolls back to server truth.
 */
export function DecisionControls({
  incident,
  onDecided,
  onNeedsReload,
}: {
  incident: Detail;
  onDecided: (next: Detail) => void;
  onNeedsReload: () => void;
}) {
  const [pending, setPending] = useState(false);
  const [response, setResponse] = useState<ResponsePlan | null>(null);
  const [error, setError] = useState<string | null>(null);

  const decidable = incident.status === "triaged";

  async function decide(kind: "approve" | "reject") {
    setPending(true);
    setError(null);
    // Optimistic: flip status locally while the request is in flight.
    const optimisticStatus = kind === "approve" ? "approved" : "rejected";
    onDecided({ ...incident, status: optimisticStatus });
    try {
      const result = kind === "approve" ? await approve(incident.id) : await reject(incident.id);
      onDecided({ ...incident, status: result.status });
      setResponse(result.response);
    } catch (err) {
      // Roll back to server truth; surface why.
      if (err instanceof ApiError) {
        setError(
          err.status === 409
            ? `Cannot decide: incident is '${err.incidentStatus ?? "not triaged"}'.`
            : err.message,
        );
      } else {
        setError("decision failed");
      }
      onNeedsReload();
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="panel">
      <h2>Human Decision</h2>
      <div className="controls">
        <button
          className="btn btn-approve"
          disabled={!decidable || pending}
          onClick={() => decide("approve")}
        >
          Approve
        </button>
        <button
          className="btn btn-reject"
          disabled={!decidable || pending}
          onClick={() => decide("reject")}
        >
          Reject
        </button>
        {!decidable && (
          <span className="muted">
            Decision available only while triaged (currently {incident.status}).
          </span>
        )}
      </div>

      {response && (
        <div className="notice notice-ok">
          <strong>Dry-run response:</strong> {response.action}
          {response.target ? ` → ${response.target}` : ""}. {response.detail}
        </div>
      )}
      {error && <div className="notice notice-error">{error}</div>}
    </section>
  );
}
