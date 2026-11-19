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

/**
 * Detection rule DSL. A rule matches a single NormalizedEvent when ALL of its
 * `when` conditions hold (logical AND). Each condition names a dotted field
 * path into the event (e.g. "actor.ip", "outcome"), an operator, and a value.
 * Kept deliberately small — enough to express the MVP's ~15 hand-written rules
 * without a general expression language.
 */
export const RuleOperator = z.enum([
  "eq", // field === value
  "neq", // field !== value
  "in", // value (array) includes field
  "gte", // field >= value (numbers)
  "lte", // field <= value (numbers)
  "contains", // field (string) includes value (string)
  "exists", // field is present / absent per boolean value
]);
export type RuleOperatorType = z.infer<typeof RuleOperator>;

export const RuleConditionSchema = z.object({
  field: z.string().min(1),
  op: RuleOperator,
  value: z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.array(z.union([z.string(), z.number()])),
  ]),
});
export type RuleCondition = z.infer<typeof RuleConditionSchema>;

/**
 * A windowed rule counts matching events keyed by a field over a time window
 * and fires when the count reaches `threshold`. When `window` is absent the
 * rule is single-event. Example: 5 `authentication` failures from one
 * `actor.ip` in 300s → brute-force.
 */
export const RuleWindowSchema = z.object({
  groupBy: z.string().min(1), // dotted field whose value buckets the count
  threshold: z.number().int().positive(),
  seconds: z.number().int().positive(),
});
export type RuleWindow = z.infer<typeof RuleWindowSchema>;

export const RuleSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
  severity: z.number().int().min(0).max(100),
  enabled: z.boolean().default(true),
  when: z.array(RuleConditionSchema).min(1),
  window: RuleWindowSchema.optional(),
});
export type Rule = z.infer<typeof RuleSchema>;

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
