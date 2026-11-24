import { v4 as uuidv4 } from "uuid";
import {
  NormalizedEventSchema,
  type NormalizedEvent,
} from "@avekshak/schema";

/**
 * Shape of a Wazuh alert document (subset we rely on). Wazuh stores alerts in
 * an Elasticsearch index; each hit's _source looks roughly like this.
 */
interface WazuhDoc {
  timestamp?: string;
  rule?: {
    level?: number; // 0..15
    description?: string;
    groups?: string[];
  };
  agent?: { name?: string; ip?: string };
  data?: {
    srcip?: string;
    srcuser?: string;
    dstuser?: string;
  };
  [k: string]: unknown;
}

/** Wazuh rule.level is 0..15; scale to 0..100. */
function levelToSeverity(level: number | undefined): number {
  if (typeof level !== "number" || Number.isNaN(level)) return 20;
  const clamped = Math.max(0, Math.min(15, level));
  return Math.round((clamped / 15) * 100);
}

function categoryFromGroups(groups: string[] | undefined): {
  category: string;
  action: string;
  outcome: NormalizedEvent["outcome"];
} {
  const g = (groups ?? []).map((x) => x.toLowerCase());
  if (g.includes("authentication_failed") || g.includes("authentication_failures")) {
    return { category: "authentication", action: "login_failed", outcome: "failure" };
  }
  if (g.includes("authentication_success")) {
    return { category: "authentication", action: "login_success", outcome: "success" };
  }
  if (g.includes("syscheck")) {
    return { category: "integrity", action: "file_changed", outcome: "unknown" };
  }
  return { category: "system", action: "alert", outcome: "unknown" };
}

/**
 * Pure normalizer: one Wazuh alert doc → NormalizedEvent, or null if the input
 * is not a usable object. Never throws.
 *
 * `id` lets the caller pass a deterministic UUID (derived from the source
 * doc's stable `_id`) so repeated polls of the same document produce the same
 * event id and can be deduped on insert. When omitted, a random id is used.
 */
export function normalizeWazuh(doc: unknown, id?: string): NormalizedEvent | null {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) return null;
  const d = doc as WazuhDoc;

  const ts = typeof d.timestamp === "string" ? toIso(d.timestamp) : new Date().toISOString();
  if (ts === null) return null;

  const { category, action, outcome } = categoryFromGroups(d.rule?.groups);

  const candidate: NormalizedEvent = {
    id: id ?? uuidv4(),
    ts,
    source: "wazuh",
    category,
    action,
    outcome,
    severity: levelToSeverity(d.rule?.level),
    actor: {
      user: d.data?.srcuser ?? d.data?.dstuser,
      ip: d.data?.srcip,
    },
    target: {
      host: d.agent?.name,
      ip: d.agent?.ip,
    },
    raw: d as Record<string, unknown>,
  };

  const parsed = NormalizedEventSchema.safeParse(candidate);
  return parsed.success ? parsed.data : null;
}

function toIso(s: string): string | null {
  const t = Date.parse(s);
  if (Number.isNaN(t)) return null;
  return new Date(t).toISOString();
}
