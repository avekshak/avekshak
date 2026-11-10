import { z } from "zod";

export const ConditionSchema = z.object({
  field: z.enum([
    "source", "category", "action", "outcome", "severity",
    "actor.user", "actor.ip", "target.host", "target.resource", "target.ip",
  ]),
  operator: z.enum(["equals", "contains", "startsWith", "gte", "lte", "gt", "lt"]),
  value: z.union([z.string(), z.number()]),
});

export const ThresholdSchema = z.object({
  count: z.number().int().positive(),
  windowSeconds: z.number().int().positive(),
  groupBy: z.enum(["actor.ip", "actor.user", "target.host"]),
}).optional();

export const RuleSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
  description: z.string().optional(),
  category: z.string().min(1),
  severity: z.number().int().min(0).max(100),
  condition: ConditionSchema,
  threshold: ThresholdSchema,
});

export type Rule = z.infer<typeof RuleSchema>;
export type Condition = z.infer<typeof ConditionSchema>;
