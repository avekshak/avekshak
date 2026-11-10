import { randomUUID } from "crypto";
import type { NormalizedEvent } from "@avekshak/schema";

interface CloudTrailRecord {
  eventTime?: string;
  eventSource?: string;
  eventName?: string;
  errorCode?: string;
  errorMessage?: string;
  userIdentity?: { type?: string; userName?: string; arn?: string };
  sourceIPAddress?: string;
  requestParameters?: Record<string, unknown>;
  responseElements?: Record<string, unknown>;
  awsRegion?: string;
  recipientAccountId?: string;
}

interface GuardDutyFinding {
  CreatedAt?: string;
  UpdatedAt?: string;
  Type?: string;
  Severity?: number;
  Title?: string;
  Description?: string;
  Service?: {
    Action?: {
      ActionType?: string;
      NetworkConnectionAction?: { RemoteIpDetails?: { IpAddressV4?: string } };
      AwsApiCallAction?: { CallerType?: string; RemoteIpDetails?: { IpAddressV4?: string } };
    };
  };
  Resource?: {
    ResourceType?: string;
    InstanceDetails?: { InstanceId?: string };
    AccessKeyDetails?: { UserName?: string };
  };
}

// CloudTrail severity: errors = higher, reads = low
function cloudTrailSeverity(record: CloudTrailRecord): number {
  if (record.errorCode) return 70;
  const name = (record.eventName ?? "").toLowerCase();
  if (name.startsWith("delete") || name.startsWith("terminate")) return 60;
  if (name.startsWith("create") || name.startsWith("put") || name.startsWith("attach")) return 30;
  return 10;
}

export function normalizeCloudTrail(raw: unknown): NormalizedEvent | null {
  const r = raw as CloudTrailRecord;
  if (!r?.eventName) return null;

  const user = r.userIdentity?.userName ?? r.userIdentity?.arn?.split("/").pop();

  return {
    id: randomUUID(),
    ts: r.eventTime ?? new Date().toISOString(),
    source: "aws",
    category: inferCTCategory(r.eventSource ?? "", r.eventName ?? ""),
    action: toSnakeCase(r.eventName ?? "unknown"),
    outcome: r.errorCode ? "failure" : "success",
    severity: cloudTrailSeverity(r),
    actor: { user, ip: r.sourceIPAddress },
    target: {
      host: undefined,
      resource: r.eventSource,
      ip: undefined,
    },
    raw: raw as Record<string, unknown>,
  };
}

export function normalizeGuardDuty(raw: unknown): NormalizedEvent | null {
  const f = raw as GuardDutyFinding;
  if (!f?.Type) return null;

  const ip =
    f.Service?.Action?.NetworkConnectionAction?.RemoteIpDetails?.IpAddressV4 ??
    f.Service?.Action?.AwsApiCallAction?.RemoteIpDetails?.IpAddressV4;

  const user =
    f.Resource?.AccessKeyDetails?.UserName;

  // GuardDuty severity 0-10 → 0-100
  const severity = Math.min(100, Math.round((f.Severity ?? 0) * 10));

  return {
    id: randomUUID(),
    ts: f.CreatedAt ?? new Date().toISOString(),
    source: "aws",
    category: inferGDCategory(f.Type ?? ""),
    action: toSnakeCase(f.Type ?? "unknown"),
    outcome: "unknown",
    severity,
    actor: { user, ip },
    target: {
      host: f.Resource?.InstanceDetails?.InstanceId,
      resource: f.Resource?.ResourceType,
    },
    raw: raw as Record<string, unknown>,
  };
}

function inferCTCategory(source: string, name: string): string {
  if (source.includes("iam") || name.toLowerCase().includes("credential")) return "authentication";
  if (source.includes("s3")) return "data_access";
  if (source.includes("ec2") || source.includes("lambda")) return "cloud";
  if (source.includes("cloudtrail") || source.includes("config")) return "audit";
  return "cloud";
}

function inferGDCategory(type: string): string {
  const lower = type.toLowerCase();
  if (lower.includes("backdoor") || lower.includes("trojan") || lower.includes("malware")) return "malware";
  if (lower.includes("recon") || lower.includes("portscan")) return "network";
  if (lower.includes("credential") || lower.includes("iam")) return "authentication";
  if (lower.includes("exfiltration") || lower.includes("s3")) return "data_access";
  return "cloud";
}

function toSnakeCase(s: string): string {
  return s.replace(/([A-Z])/g, "_$1").toLowerCase().replace(/^_/, "");
}
