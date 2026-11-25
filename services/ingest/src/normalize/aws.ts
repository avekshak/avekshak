import { v4 as uuidv4 } from "uuid";
import {
  NormalizedEventSchema,
  type NormalizedEvent,
} from "@avekshak/schema";

interface CloudTrailRecord {
  eventTime?: string;
  eventName?: string;
  eventSource?: string;
  sourceIPAddress?: string;
  errorCode?: string;
  awsRegion?: string;
  userIdentity?: { userName?: string; arn?: string; type?: string };
  [k: string]: unknown;
}

interface GuardDutyFinding {
  updatedAt?: string;
  createdAt?: string;
  type?: string;
  severity?: number; // 0..10 (float)
  region?: string;
  title?: string;
  resource?: { resourceType?: string };
  [k: string]: unknown;
}

/** GuardDuty severity is 0..10 (float); scale to 0..100. */
function gdSeverity(sev: number | undefined): number {
  if (typeof sev !== "number" || Number.isNaN(sev)) return 50;
  return Math.round(Math.max(0, Math.min(10, sev)) * 10);
}

function isGuardDuty(o: Record<string, unknown>): boolean {
  return "type" in o && ("service" in o || "resource" in o || "severity" in o) && !("eventName" in o);
}

function isCloudTrail(o: Record<string, unknown>): boolean {
  return "eventName" in o || "eventSource" in o;
}

/**
 * Pure normalizer: a single AWS record (CloudTrail event OR GuardDuty finding)
 * → NormalizedEvent, or null if unrecognized/malformed. Never throws.
 *
 * `id` lets the caller pass a deterministic UUID (derived from the record's
 * stable id — CloudTrail eventID or GuardDuty finding id) so re-ingesting the
 * same export produces the same event id and dedupes on insert.
 */
export function normalizeAws(record: unknown, id?: string): NormalizedEvent | null {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    return null;
  }
  const o = record as Record<string, unknown>;

  let candidate: NormalizedEvent | null = null;
  if (isCloudTrail(o)) {
    candidate = fromCloudTrail(o as CloudTrailRecord, id);
  } else if (isGuardDuty(o)) {
    candidate = fromGuardDuty(o as GuardDutyFinding, id);
  } else {
    return null;
  }
  if (candidate === null) return null;

  const parsed = NormalizedEventSchema.safeParse(candidate);
  return parsed.success ? parsed.data : null;
}

function fromCloudTrail(r: CloudTrailRecord, id?: string): NormalizedEvent | null {
  const ts = r.eventTime ? toIso(r.eventTime) : new Date().toISOString();
  if (ts === null) return null;
  const failed = typeof r.errorCode === "string" && r.errorCode.length > 0;
  return {
    id: id ?? uuidv4(),
    ts,
    source: "aws",
    category: "cloud",
    action: r.eventName ?? "api_call",
    outcome: failed ? "failure" : "success",
    severity: failed ? 50 : 20,
    actor: {
      user: r.userIdentity?.userName ?? r.userIdentity?.arn,
      ip: r.sourceIPAddress,
    },
    target: {
      resource: r.eventSource,
    },
    location: r.awsRegion ? { city: r.awsRegion } : undefined,
    raw: r as Record<string, unknown>,
  };
}

function fromGuardDuty(f: GuardDutyFinding, id?: string): NormalizedEvent | null {
  const ts =
    toIso(f.updatedAt ?? f.createdAt ?? "") ?? new Date().toISOString();
  return {
    id: id ?? uuidv4(),
    ts,
    source: "aws",
    category: "cloud",
    action: f.type ?? "guardduty_finding",
    outcome: "unknown",
    severity: gdSeverity(f.severity),
    actor: {},
    target: {
      resource: f.resource?.resourceType,
    },
    location: f.region ? { city: f.region } : undefined,
    raw: f as Record<string, unknown>,
  };
}

function toIso(s: string): string | null {
  if (s.length === 0) return null;
  const t = Date.parse(s);
  if (Number.isNaN(t)) return null;
  return new Date(t).toISOString();
}
