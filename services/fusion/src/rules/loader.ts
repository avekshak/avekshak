import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { RuleSchema, type Rule } from "@avekshak/schema";

/** Thrown when a rule file is syntactically or structurally invalid. */
export class RuleLoadError extends Error {
  constructor(
    public readonly file: string,
    message: string,
  ) {
    super(`${file}: ${message}`);
    this.name = "RuleLoadError";
  }
}

/**
 * Parse one YAML document into a list of validated Rules. A document may hold
 * either a single rule (a mapping) or a list of rules (a sequence). Every rule
 * is validated against RuleSchema; the first failure throws RuleLoadError with
 * a human-readable path so a bad rule file is caught at startup, not at runtime.
 */
export function loadRulesFromString(contents: string, file = "<string>"): Rule[] {
  let doc: unknown;
  try {
    doc = parseYaml(contents);
  } catch (err) {
    throw new RuleLoadError(file, `invalid YAML: ${(err as Error).message}`);
  }
  if (doc === null || doc === undefined) return [];

  const raw = Array.isArray(doc) ? doc : [doc];
  const rules: Rule[] = [];
  for (let i = 0; i < raw.length; i += 1) {
    const parsed = RuleSchema.safeParse(raw[i]);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      const where = issue?.path.join(".") || "(root)";
      throw new RuleLoadError(
        file,
        `rule[${i}] invalid at "${where}": ${issue?.message ?? "unknown"}`,
      );
    }
    rules.push(parsed.data);
  }
  return rules;
}

/**
 * Load every *.yaml / *.yml file in a directory into a flat, deduplicated-by-id
 * list of enabled+disabled rules. Duplicate rule ids across files are a hard
 * error — ids must be globally unique so alerts attribute unambiguously.
 */
export async function loadRulesFromDir(dir: string): Promise<Rule[]> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch (err) {
    throw new Error(`cannot read rules dir ${dir}: ${(err as Error).message}`);
  }
  const files = entries
    .filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"))
    .sort();

  const byId = new Map<string, string>(); // ruleId → file it came from
  const all: Rule[] = [];
  for (const f of files) {
    const full = path.join(dir, f);
    const contents = await readFile(full, "utf8");
    for (const rule of loadRulesFromString(contents, f)) {
      const prior = byId.get(rule.id);
      if (prior) {
        throw new RuleLoadError(
          f,
          `duplicate rule id "${rule.id}" (already defined in ${prior})`,
        );
      }
      byId.set(rule.id, f);
      all.push(rule);
    }
  }
  return all;
}
