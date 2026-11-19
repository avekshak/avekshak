import type {
  NormalizedEvent,
  Rule,
  RuleCondition,
} from "@avekshak/schema";

/** Resolve a dotted path (e.g. "actor.ip") against an event. */
export function resolveField(ev: NormalizedEvent, path: string): unknown {
  let cur: unknown = ev;
  for (const part of path.split(".")) {
    if (cur === null || cur === undefined || typeof cur !== "object") {
      return undefined;
    }
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

/** Evaluate a single condition against an event. Never throws. */
export function matchesCondition(
  ev: NormalizedEvent,
  cond: RuleCondition,
): boolean {
  const actual = resolveField(ev, cond.field);
  const { op, value } = cond;

  switch (op) {
    case "eq":
      return actual === value;
    case "neq":
      return actual !== value;
    case "in":
      return (
        Array.isArray(value) &&
        value.some((v) => v === actual)
      );
    case "gte":
      return (
        typeof actual === "number" &&
        typeof value === "number" &&
        actual >= value
      );
    case "lte":
      return (
        typeof actual === "number" &&
        typeof value === "number" &&
        actual <= value
      );
    case "contains":
      return (
        typeof actual === "string" &&
        typeof value === "string" &&
        actual.includes(value)
      );
    case "exists": {
      const present = actual !== undefined && actual !== null;
      return value === true ? present : !present;
    }
    default:
      return false;
  }
}

/** A rule matches when ALL its conditions hold (logical AND). */
export function matchesRule(ev: NormalizedEvent, rule: Rule): boolean {
  if (!rule.enabled) return false;
  return rule.when.every((c) => matchesCondition(ev, c));
}

/**
 * Evaluate an event against a set of rules, returning the single-event rules
 * that match. Windowed rules are evaluated separately (they also need their
 * `when` conditions to pass first, then a count threshold), so this returns
 * them split out for the caller to feed into the windowed counter.
 */
export interface EvalResult {
  /** Single-event rules that fired outright. */
  matched: Rule[];
  /** Windowed rules whose per-event conditions passed (count still pending). */
  windowCandidates: Rule[];
}

export function evaluate(ev: NormalizedEvent, rules: Rule[]): EvalResult {
  const matched: Rule[] = [];
  const windowCandidates: Rule[] = [];
  for (const rule of rules) {
    if (!matchesRule(ev, rule)) continue;
    if (rule.window) {
      windowCandidates.push(rule);
    } else {
      matched.push(rule);
    }
  }
  return { matched, windowCandidates };
}
