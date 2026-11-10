import { randomUUID } from "crypto";
import type { NormalizedEvent } from "@avekshak/schema";

// RFC 3164 syslog: <priority>timestamp hostname process[pid]: message
const SYSLOG_RE =
  /^<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$/;

function parsePriority(pri: number): { severity: number; facility: number } {
  return { facility: pri >> 3, severity: pri & 0x7 };
}

// Map syslog severity (0=emerg … 7=debug) to 0-100 scale
function syslogSeverityToScore(sev: number): number {
  const map: Record<number, number> = { 0: 100, 1: 90, 2: 80, 3: 70, 4: 50, 5: 30, 6: 10, 7: 5 };
  return map[sev] ?? 10;
}

export function normalizeSyslog(raw: unknown): NormalizedEvent | null {
  if (typeof raw !== "string") return null;
  const m = SYSLOG_RE.exec(raw.trim());
  if (!m) return null;

  const [, priStr, , hostname, process_, , message] = m;
  const { severity: sev } = parsePriority(Number(priStr));

  const action = inferAction(message ?? "");

  return {
    id: randomUUID(),
    ts: new Date().toISOString(),
    source: "syslog",
    category: inferCategory(process_ ?? "", message ?? ""),
    action,
    outcome: inferOutcome(message ?? ""),
    severity: syslogSeverityToScore(sev),
    actor: { user: extractUser(message ?? ""), ip: undefined },
    target: { host: hostname, resource: process_ ?? undefined },
    raw: { line: raw },
  };
}

function inferAction(msg: string): string {
  const lower = msg.toLowerCase();
  if (lower.includes("failed password") || lower.includes("authentication failure")) return "login_failed";
  if (lower.includes("accepted password") || lower.includes("session opened")) return "login_success";
  if (lower.includes("session closed")) return "logout";
  if (lower.includes("sudo")) return "privilege_escalation";
  return "log_entry";
}

function inferCategory(process_: string, msg: string): string {
  const lower = (process_ + " " + msg).toLowerCase();
  if (lower.includes("sshd") || lower.includes("login") || lower.includes("pam")) return "authentication";
  if (lower.includes("sudo") || lower.includes("su ")) return "authorization";
  if (lower.includes("kernel") || lower.includes("iptables")) return "network";
  return "system";
}

function inferOutcome(msg: string): "success" | "failure" | "unknown" {
  const lower = msg.toLowerCase();
  if (lower.includes("fail") || lower.includes("error") || lower.includes("invalid") || lower.includes("denied")) return "failure";
  if (lower.includes("accept") || lower.includes("success") || lower.includes("opened")) return "success";
  return "unknown";
}

function extractUser(msg: string): string | undefined {
  const m = /(?:user|for)\s+(\w+)/i.exec(msg);
  return m?.[1];
}
