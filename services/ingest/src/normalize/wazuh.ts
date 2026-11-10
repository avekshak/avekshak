import { randomUUID } from "crypto";
import type { NormalizedEvent } from "@avekshak/schema";

interface WazuhHit {
  _source?: {
    timestamp?: string;
    agent?: { name?: string; ip?: string };
    rule?: { description?: string; level?: number; groups?: string[] };
    data?: {
      srcip?: string;
      dstip?: string;
      srcuser?: string;
      dstuser?: string;
      url?: string;
    };
    full_log?: string;
  };
}

// Wazuh rule level 0-15 → 0-100
function wazuhLevelToScore(level: number): number {
  return Math.min(100, Math.round((level / 15) * 100));
}

export function normalizeWazuh(raw: unknown): NormalizedEvent | null {
  const hit = raw as WazuhHit;
  const src = hit?._source;
  if (!src) return null;

  const rule = src.rule ?? {};
  const data = src.data ?? {};
  const groups: string[] = rule.groups ?? [];

  return {
    id: randomUUID(),
    ts: src.timestamp ?? new Date().toISOString(),
    source: "wazuh",
    category: inferCategory(groups),
    action: inferAction(groups, rule.description ?? ""),
    outcome: inferOutcome(groups, rule.description ?? ""),
    severity: wazuhLevelToScore(rule.level ?? 0),
    actor: {
      user: data.srcuser ?? undefined,
      ip: data.srcip ?? src.agent?.ip ?? undefined,
    },
    target: {
      host: src.agent?.name ?? undefined,
      resource: data.url ?? undefined,
      ip: data.dstip ?? undefined,
    },
    raw: raw as Record<string, unknown>,
  };
}

function inferCategory(groups: string[]): string {
  if (groups.some((g) => ["authentication_failed", "authentication_success", "pam"].includes(g))) return "authentication";
  if (groups.some((g) => g.includes("web"))) return "network";
  if (groups.some((g) => g.includes("malware") || g.includes("virus"))) return "malware";
  if (groups.some((g) => g.includes("intrusion"))) return "intrusion";
  return "system";
}

function inferAction(groups: string[], desc: string): string {
  if (groups.includes("authentication_failed")) return "login_failed";
  if (groups.includes("authentication_success")) return "login_success";
  if (desc.toLowerCase().includes("brute")) return "brute_force";
  if (desc.toLowerCase().includes("scan")) return "port_scan";
  return "alert";
}

function inferOutcome(groups: string[], desc: string): "success" | "failure" | "unknown" {
  if (groups.includes("authentication_failed")) return "failure";
  if (groups.includes("authentication_success")) return "success";
  if (desc.toLowerCase().includes("fail") || desc.toLowerCase().includes("block")) return "failure";
  return "unknown";
}
