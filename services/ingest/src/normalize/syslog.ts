import { v4 as uuidv4 } from "uuid";
import {
  NormalizedEventSchema,
  type NormalizedEvent,
} from "@avekshak/schema";

function priToSeverity(pri: number): number {
  const sev = pri % 8;
  return Math.round(((7 - sev) / 7) * 100);
}

const IPV4 = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;

export function normalizeSyslog(line: string): NormalizedEvent | null {
  if (typeof line !== "string") return null;
  const trimmed = line.trim();
  if (trimmed.length === 0) return null;

  let severity = 30;
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

  const hostMatch = /(\S+)\s+sshd/.exec(body);
  const host = hostMatch?.[1]?.slice(0, 253);

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
