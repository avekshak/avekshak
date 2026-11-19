import { v5 as uuidv5 } from "uuid";
import type { Alert, NormalizedEvent, Rule } from "@avekshak/schema";

/** Namespace for deriving stable alert ids from (rule, dedupeKey). */
const ALERT_NS = "3f8a1c2b-6d7e-5a4b-9c0d-1e2f3a4b5c6d";

/** Width of the dedupe time bucket, in milliseconds (5 minutes). */
export const DEDUPE_WINDOW_MS = 5 * 60 * 1000;

/**
 * A dedupe key collapses "the same alert" within a short window into one row.
 * Same rule + same actor/target identity + same 5-minute bucket → identical
 * key → unique-constraint suppresses the duplicate insert. The bucket is
 * derived from the event timestamp (not wall-clock) so replaying an export is
 * deterministic.
 */
export function dedupeKey(ev: NormalizedEvent, rule: Rule): string {
  const bucket = Math.floor(Date.parse(ev.ts) / DEDUPE_WINDOW_MS);
  const actorIp = ev.actor.ip ?? "-";
  const actorUser = ev.actor.user ?? "-";
  const targetHost = ev.target.host ?? "-";
  return `${rule.id}|${actorIp}|${actorUser}|${targetHost}|${bucket}`;
}

/**
 * Pure: build an Alert from a matched event+rule. The alert id is a UUIDv5 of
 * the dedupe key, so a suppressed duplicate would have produced the same id —
 * promotion is idempotent end to end. Alert severity takes the rule's severity
 * (the rule encodes the analyst's judgment, overriding the raw event severity).
 */
export function buildAlert(
  ev: NormalizedEvent,
  rule: Rule,
): { alert: Alert; dedupeKey: string } {
  const key = dedupeKey(ev, rule);
  const alert: Alert = {
    id: uuidv5(key, ALERT_NS),
    eventId: ev.id,
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    ts: ev.ts,
    actorIp: ev.actor.ip,
    actorUser: ev.actor.user,
    targetHost: ev.target.host,
  };
  return { alert, dedupeKey: key };
}
