import { v4 as uuidv4 } from "uuid";
import {
  NormalizedEventSchema,
  type NormalizedEvent,
} from "@avekshak/schema";

/**
 * Maps a syslog PRI value (0-191) to a 0-100 severity.
 * Syslog severity is the low 3 bits: 0 (emerg) .. 7 (debug).
 * We invert so emerg=100, debug≈12.
 */
function priToSeverity(pri: number): number {
  const sev = pri % 8; // 0..7
  return Math.round(((7 - sev) / 7) * 100);
}

const IPV4 = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;

/**
 * Pure normalizer: a single raw syslog line → NormalizedEvent, or null if
 * the line is empty/unparseable. Never throws — callers log+skip on null.
 *
 * Handles the common auth patterns the MVP cares about (sshd Failed/Accepted
 * password). Everything else becomes a generic, low-severity system event so
 * nothing is silently dropped.
 */
export function normalizeSyslog(line: string): NormalizedEvent | null {
  if (typeof line !== "string") return null;
  const trimmed = line.trim();
  if (trimmed.length === 0) return null;

  // Optional "<PRI>" prefix per RFC3164/5424.
  let severity = 30; // default: informational-ish
  let body = trimmed;
  const priMatch = /^<(\d{1,3})>/.exec(trimmed);
  if (priMatch) {
    const pri = Number(priMatch[1]);
    if (pri >= 0 && pri <= 191) severity = priToSeverity(pri);
    body = trimmed.slice(priMatch[0].length);
  }

  const lower = body.toLowerCase();
  const ipMatch = IPV4.exec(body);
  const ip = ipMatch ? ipMatch[1] : undefined;

  // sshd auth: "Failed password for <user> from <ip>" / "Accepted password..."
  let action = "log";
  let outcome: NormalizedEvent["outcome"] = "unknown";
  let category = "system";
  let user: string | undefined;

  const sshUser = /for (?:invalid user )?(\S+) from/.exec(body);
  if (sshUser) user = sshUser[1];

  if (lower.includes("failed password") || lower.includes("authentication failure")) {
    category = "authentication";
    action = "login_failed";
    outcome = "failure";
    if (severity < 50) severity = 50;
  } else if (lower.includes("accepted password") || lower.includes("session opened")) {
    category = "authentication";
    action = "login_success";
    outcome = "success";
  }

  const host = /(\w[\w.-]*)\s+sshd/.exec(body)?.[1];

  const candidate: NormalizedEvent = {
    id: uuidv4(),
    ts: new Date().toISOString(),
    source: "syslog",
    category,
    action,
    outcome,
    severity,
    actor: { user, ip },
    target: { host },
    raw: { line: trimmed },
  };

  const parsed = NormalizedEventSchema.safeParse(candidate);
  return parsed.success ? parsed.data : null;
}
