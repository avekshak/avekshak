/**
 * Severity vocabularies + a boundary-aware matcher.
 *
 * Ported from AiSOC's app/keywords.py. The whole point of this module over a
 * naive `text.includes("c2")` is two bugs it refuses to repeat (AiSOC #1607):
 *
 * 1. A substring test fires on identifiers. "c2" is inside every AWS private
 *    hostname `ip-10-0-1-7.ec2.internal`, every EC2 instance id, and plenty of
 *    hex digests — so a harmless alert got scored critical and silently skipped
 *    the LLM tier. We match only at token boundaries.
 * 2. Token boundaries alone still let "c2" match a MAC octet `...:c2:...` or the
 *    "c2" pair of a dotted hex digest, because the delimiters of a MAC ARE token
 *    boundaries. So `normalise` strikes opaque identifiers (MAC / UUID / hash)
 *    out of the haystack first: they carry no words, only coincidences.
 *
 * A trailing `*` marks a stem — matched at the left boundary only — because
 * "credential dump" has to reach "credential dumping" and "beacon" has to reach
 * "beaconing". Giving up the right boundary is only safe for a keyword long
 * enough that it cannot begin a run inside an identifier.
 */

/** A keyword ending in this is matched as a prefix — left boundary only. */
export const STEM_SUFFIX = "*";

/**
 * Behaviour and tooling that make an incident critical on sight.
 * `beacon*` / `credential dump*` are stems: "C2 beaconing" and "credential
 * dumping" are the ordinary way those behaviours are written.
 */
export const CRITICAL_KEYWORDS: readonly string[] = [
  "beacon*",
  "c2",
  "cobalt strike",
  "credential dump*",
  "data breach",
  "exfiltration",
  "lateral movement",
  "mimikatz",
  "ransomware",
  "rootkit",
  "supply chain",
  "zero-day",
];

/**
 * Serious, but not critical on sight. `domain admin` lives here, not in the
 * critical set: every other critical entry names a behaviour or a tool, while
 * this names an account tier that turns up in routine group-membership audits.
 * The behavioural form of the same concern — `privilege escalation` — is high.
 */
export const HIGH_KEYWORDS: readonly string[] = [
  "anomaly",
  "backdoor",
  "brute force*",
  "domain admin",
  "exploit*",
  "malware",
  "phishing",
  "privilege escalation",
  "suspicious login",
];

/**
 * Values that are opaque by construction: whatever letters they contain are an
 * accident of encoding, so a keyword found inside one coincided with it rather
 * than occurred in it. Ordered longest-shape-first so a MAC address is consumed
 * whole rather than leaving fragments behind. `g` so every occurrence is blanked.
 */
const OPAQUE =
  /(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|(?<![0-9a-z])[0-9a-f]{12,}(?![0-9a-z])/g;

/**
 * Lowercase, and blank out opaque identifiers. A hash, a UUID and a MAC address
 * carry no words; leaving them in means a keyword can match a run of hex that
 * happens to spell it — which no boundary rule can prevent.
 */
export function normalise(text: string): string {
  return text.toLowerCase().replace(OPAQUE, " ");
}

/** The keyword as a human reads it, with any stem marker removed. */
export function display(keyword: string): string {
  return keyword.endsWith(STEM_SUFFIX)
    ? keyword.slice(0, -STEM_SUFFIX.length)
    : keyword;
}

function isAlnum(ch: string): boolean {
  return /[a-z0-9]/i.test(ch);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const patternCache = new Map<string, RegExp>();

/**
 * Compile one keyword into its boundary-aware pattern. A boundary is asserted
 * only on an edge whose own character is alphanumeric — `.lockbit` is meant to
 * match a file extension, so demanding a boundary before its leading dot would
 * stop it matching the very thing it is for. The right boundary is dropped for
 * stems.
 */
function pattern(keyword: string): RegExp {
  const cached = patternCache.get(keyword);
  if (cached) return cached;
  const stem = keyword.endsWith(STEM_SUFFIX);
  const body = display(keyword);
  const left = body.length > 0 && isAlnum(body[0]!) ? "(?<![a-z0-9])" : "";
  const right =
    stem || body.length === 0 ? "" : isAlnum(body[body.length - 1]!) ? "(?![a-z0-9])" : "";
  const re = new RegExp(`${left}${escapeRegExp(body)}${right}`);
  patternCache.set(keyword, re);
  return re;
}

/**
 * True when `keyword` occurs in `text` at a token boundary. `text` is expected
 * already lowercased + opaque-blanked (see `normalise`).
 */
export function matches(text: string, keyword: string): boolean {
  return pattern(keyword).test(text);
}

/** Display forms of every keyword that matches, sorted for stable output. */
export function matched(text: string, keywords: readonly string[]): string[] {
  return keywords
    .filter((kw) => matches(text, kw))
    .map(display)
    .sort();
}

export function anyMatched(text: string, keywords: readonly string[]): boolean {
  return keywords.some((kw) => matches(text, kw));
}
