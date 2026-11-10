import type { NormalizedEvent } from "@avekshak/schema";
import type { Rule, Condition } from "./rule-schema.js";

function getField(event: NormalizedEvent, field: Condition["field"]): string | number | undefined {
  switch (field) {
    case "source": return event.source;
    case "category": return event.category;
    case "action": return event.action;
    case "outcome": return event.outcome;
    case "severity": return event.severity;
    case "actor.user": return event.actor.user;
    case "actor.ip": return event.actor.ip;
    case "target.host": return event.target.host;
    case "target.resource": return event.target.resource;
    case "target.ip": return event.target.ip;
  }
}

function matchesCondition(event: NormalizedEvent, condition: Condition): boolean {
  const actual = getField(event, condition.field);
  if (actual === undefined || actual === null) return false;

  const { operator, value } = condition;

  switch (operator) {
    case "equals":
      return String(actual).toLowerCase() === String(value).toLowerCase();
    case "contains":
      return String(actual).toLowerCase().includes(String(value).toLowerCase());
    case "startsWith":
      return String(actual).toLowerCase().startsWith(String(value).toLowerCase());
    case "gte": return Number(actual) >= Number(value);
    case "lte": return Number(actual) <= Number(value);
    case "gt":  return Number(actual) > Number(value);
    case "lt":  return Number(actual) < Number(value);
    default: return false;
  }
}

export function evaluateRules(event: NormalizedEvent, rules: Rule[]): Rule[] {
  return rules.filter((rule) => {
    // Threshold rules are evaluated separately by the windowed counter
    if (rule.threshold) return false;
    return matchesCondition(event, rule.condition);
  });
}
