import type { Alert, NormalizedEvent, Verdict } from "@avekshak/schema";

/**
 * The bundle of facts handed to the LLM for one incident. Assembled by the
 * triage worker from Postgres (the incident, its linked alerts, and the events
 * behind those alerts). Kept provider-agnostic so any LLM backend sees the same
 * shape.
 */
export interface IncidentContext {
  incidentId: string;
  title: string;
  severity: number;
  correlationKey: string;
  createdAt: string;
  alerts: Alert[];
  events: NormalizedEvent[];
}

/**
 * A pluggable LLM backend. The only job is: given an incident context, return a
 * schema-valid Verdict. Implementations own their own transport + retry of the
 * raw call; the triage pipeline validates and retries at the semantic level.
 */
export interface LlmProvider {
  readonly name: string;
  triage(ctx: IncidentContext): Promise<Verdict>;
  close(): Promise<void>;
}

/** Thrown when the model's output can't be coerced into a valid Verdict after retries. */
export class LlmOutputError extends Error {
  constructor(
    message: string,
    readonly raw: string,
  ) {
    super(message);
    this.name = "LlmOutputError";
  }
}
