import type { Incident } from "@avekshak/schema";

/** What a response action would have done, had this not been a dry run. */
export interface ResponsePlan {
  dryRun: true;
  action: string;
  target: string | null;
  detail: string;
}

/**
 * The MVP "response" is a dry run: it decides what it *would* do and logs it,
 * but changes nothing. Its whole job is to prove the human gate — it only ever
 * runs from the approved branch of `decideIncident`, never on its own and never
 * for a rejected incident. Swapping in a real action later means replacing the
 * body here; the gate that guards it does not move.
 *
 * We derive a concrete target (the attacker IP) from the incident's correlation
 * key when it is IP-based, so the dry run reads like the real thing.
 */
export function planResponse(incident: Incident): ResponsePlan {
  const ipMatch = /^ip:(.+)$/.exec(incident.correlationKey);
  const target = ipMatch ? ipMatch[1] : null;
  const action = target ? "block_ip" : "notify_only";
  const detail = target
    ? `DRY RUN: would block source IP ${target} for incident "${incident.title}"`
    : `DRY RUN: no IP target on incident "${incident.title}"; would notify on-call only`;
  return { dryRun: true, action, target, detail };
}
