import { z } from "zod";

/**
 * NormalizedEvent — the single contract every connector targets.
 * Flat, OCSF-inspired envelope. Frozen early because every downstream
 * stage (detection, correlation, triage) depends on this shape.
 */
export const NormalizedEventSchema = z.object({
  id: z.string().uuid(),
  ts: z.string().datetime(),
  source: z.enum(["syslog", "wazuh", "aws"]),
  category: z.string().min(1),
  action: z.string().min(1),
  outcome: z.enum(["success", "failure", "unknown"]),
  severity: z.number().int().min(0).max(100),
  actor: z.object({
    user: z.string().optional(),
    ip: z.string().optional(),
  }),
  target: z.object({
    host: z.string().optional(),
    resource: z.string().optional(),
    ip: z.string().optional(),
  }),
  location: z
    .object({
      country: z.string().optional(),
      city: z.string().optional(),
    })
    .optional(),
  raw: z.record(z.unknown()),
});
export type NormalizedEvent = z.infer<typeof NormalizedEventSchema>;

export const AlertSchema = z.object({
  id: z.string().uuid(),
  eventId: z.string().uuid(),
  ruleId: z.string().min(1),
  title: z.string().min(1),
  severity: z.number().int().min(0).max(100),
  ts: z.string().datetime(),
  actorIp: z.string().optional(),
  actorUser: z.string().optional(),
  targetHost: z.string().optional(),
});
export type Alert = z.infer<typeof AlertSchema>;

export const IncidentStatus = z.enum([
  "open",
  "triaged",
  "approved",
  "rejected",
  "closed",
]);
export type IncidentStatusType = z.infer<typeof IncidentStatus>;

export const VerdictSchema = z.object({
  verdict: z.enum(["benign", "suspicious", "critical"]),
  confidence: z.number().min(0).max(100),
  rationale: z.string().min(1),
  recommendedAction: z.string().min(1),
});
export type Verdict = z.infer<typeof VerdictSchema>;

export const IncidentSchema = z.object({
  id: z.string().uuid(),
  title: z.string().min(1),
  status: IncidentStatus,
  severity: z.number().int().min(0).max(100),
  correlationKey: z.string().min(1),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  verdict: VerdictSchema.nullable(),
});
export type Incident = z.infer<typeof IncidentSchema>;

export const LedgerEntrySchema = z.object({
  id: z.string().uuid(),
  incidentId: z.string().uuid(),
  seq: z.number().int().nonnegative(),
  ts: z.string().datetime(),
  actor: z.enum(["agent", "system", "human"]),
  action: z.string().min(1),
  detail: z.record(z.unknown()),
});
export type LedgerEntry = z.infer<typeof LedgerEntrySchema>;

export const ApprovalSchema = z.object({
  id: z.string().uuid(),
  incidentId: z.string().uuid(),
  decision: z.enum(["approved", "rejected"]),
  decidedBy: z.string().min(1),
  decidedAt: z.string().datetime(),
  note: z.string().optional(),
});
export type Approval = z.infer<typeof ApprovalSchema>;
