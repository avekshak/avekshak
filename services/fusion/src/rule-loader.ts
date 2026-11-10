import { readdir, readFile } from "fs/promises";
import { join } from "path";
import yaml from "js-yaml";
import { RuleSchema, type Rule } from "./rule-schema.js";

const RULES_DIR = process.env.RULES_DIR ?? "./rules";

export async function loadRules(dir: string = RULES_DIR): Promise<Rule[]> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    console.warn(`[fusion] rules directory not found: ${dir}`);
    return [];
  }

  const rules: Rule[] = [];

  for (const file of entries.filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"))) {
    const filePath = join(dir, file);
    let content: string;
    try {
      content = await readFile(filePath, "utf8");
    } catch {
      console.warn(`[fusion] could not read rule file: ${filePath}`);
      continue;
    }

    let parsed: unknown;
    try {
      parsed = yaml.load(content);
    } catch (err) {
      console.error(`[fusion] invalid YAML in ${file}:`, (err as Error).message);
      continue;
    }

    const result = RuleSchema.safeParse(parsed);
    if (!result.success) {
      console.error(`[fusion] rule validation failed for ${file}:`, result.error.flatten());
      continue;
    }

    rules.push(result.data);
  }

  console.log(`[fusion] loaded ${rules.length} rules from ${dir}`);
  return rules;
}
