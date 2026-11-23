/**
 * Ranking for fix-diff candidates: how many points a changed export earns, and why. Every point
 * comes with a reason, so a reader can see what the rank rests on. Heuristic, never a verdict.
 */
import type { AdvisoryHints, VulnerableSymbolCandidate } from "./fix-diff.js";

type ScoredCandidate = Omit<VulnerableSymbolCandidate, "score" | "reasons">;

export function tokenDelta(
  oldTokens: Set<string>,
  newTokens: Set<string>,
): { added: string[]; removed: string[] } {
  return {
    added: [...newTokens].filter((token) => !oldTokens.has(token)).toSorted(),
    removed: [...oldTokens].filter((token) => !newTokens.has(token)).toSorted(),
  };
}

/** CWE id -> predicate over a token (identifier or literal) that suggests the fix touches that class. */
interface CweHint {
  ids: readonly number[];
  label: string;
  matches(token: string): boolean;
}

const REGEX_LITERAL = /^\/.+\/[a-z]*$/s;

/**
 * Small static table of vocabulary typical of fixes for common weakness classes. It only decides
 * how a candidate is ranked, and every use is reported in `reasons`.
 */
const CWE_HINTS: readonly CweHint[] = [
  {
    ids: [1333, 185, 186, 400, 405, 770, 407],
    label: "regular expression or size limit",
    matches: (token) =>
      REGEX_LITERAL.test(token) || /^(regexp|limit|max\w*|timeout|length)$/i.test(token),
  },
  {
    ids: [77, 78, 88, 74],
    label: "command construction or escaping",
    matches: (token) =>
      /^(exec|execsync|spawn|spawnsync|shell|escape\w*|quote\w*|sanitize\w*)$/i.test(token),
  },
  {
    ids: [22, 23, 36, 73, 59],
    label: "path handling",
    matches: (token) =>
      /^(resolve|normalize|relative|isabsolute|basename|sep)$/i.test(token) ||
      token === ".." ||
      token.includes("../"),
  },
  {
    ids: [1321, 915, 471],
    label: "prototype or own-property handling",
    matches: (token) =>
      /^(__proto__|constructor|prototype|hasownproperty|issafekey\w*)$/i.test(token),
  },
  {
    ids: [79, 80, 116, 83],
    label: "output escaping",
    matches: (token) =>
      /^(escape\w*|sanitize\w*|encode\w*|htmlentities)$/i.test(token) ||
      /^&(amp|lt|gt|quot);?$/.test(token),
  },
  {
    ids: [94, 95, 96, 917, 1336],
    label: "dynamic code or identifier validation",
    matches: (token) =>
      /^(eval|function|runinnewcontext|runinthiscontext)$/i.test(token) ||
      /(forbidden|unsafe|illegal|invalid)/i.test(token),
  },
  {
    ids: [20, 1284, 129, 190, 191],
    label: "input validation",
    matches: (token) =>
      /^(typeof|isfinite|isnan|isinteger|validate\w*|assert\w*|typeerror|rangeerror)$/i.test(token),
  },
  {
    ids: [601, 918, 441],
    label: "URL or host validation",
    matches: (token) => /^(url|hostname|host|origin|protocol|localhost)$/i.test(token),
  },
  {
    ids: [347, 295, 297, 327, 328, 330, 338],
    label: "signature or cryptography",
    matches: (token) =>
      /^(verify|signature|algorithms?|alg|random\w*|createhash|timingsafeequal)$/i.test(token),
  },
];

/** Parse `CWE-123`, `cwe 123` and bare numbers. */
export function parseCweIds(
  values: readonly string[] | undefined,
  text: string | undefined,
): number[] {
  const ids = new Set<number>();
  for (const value of values ?? []) {
    const match = /(\d+)/.exec(value);
    if (match?.[1]) ids.add(Number.parseInt(match[1], 10));
  }
  for (const match of (text ?? "").matchAll(/CWE[-\s:]*(\d{1,5})/gi)) {
    if (match[1]) ids.add(Number.parseInt(match[1], 10));
  }
  return [...ids].toSorted((a, b) => a - b);
}

const STOP_WORDS = new Set([
  "default",
  "module",
  "exports",
  "function",
  "string",
  "object",
  "value",
  "values",
  "error",
  "version",
  "package",
  "before",
  "after",
  "which",
  "where",
  "when",
  "this",
  "that",
  "with",
  "from",
  "into",
  "have",
  "does",
  "allows",
  "allow",
  "attacker",
  "attackers",
  "remote",
  "arbitrary",
  "vulnerable",
  "vulnerability",
  "affected",
  "fixed",
  "issue",
  "input",
  "could",
  "would",
  "should",
  "using",
  "used",
  "uses",
  "cause",
  "causes",
]);

export function wordsOf(text: string): Set<string> {
  return new Set([...text.toLowerCase().matchAll(/[a-z_$][\w$]*/g)].map((match) => match[0]));
}

interface Points {
  points: number;
  reason: string;
}

/** What the kind of change is worth on its own. */
function basisPoints(candidate: ScoredCandidate, depth: number): Points {
  if (candidate.basis === "direct") {
    return candidate.kind === "value"
      ? { points: 40, reason: "an exported value (not a function) changed" }
      : { points: 100, reason: "the export's own implementation changed" };
  }
  if (candidate.basis === "removed-in-fix") {
    return { points: 55, reason: "the export was removed in the fixed version" };
  }
  if (candidate.basis === "via-internal-function") {
    const hops = `${depth} call hop${depth === 1 ? "" : "s"} away`;
    return {
      points: Math.max(15, 40 - 8 * (depth - 1)),
      reason: `depends on changed internal function ${candidate.via.join(", ")} (${hops})`,
    };
  }
  return { points: 20, reason: `its module imports changed module ${candidate.via.join(", ")}` };
}

/** A small, targeted change is more likely to be the fix than a rewrite. */
function sizePoints(candidate: ScoredCandidate): Points[] {
  const size = candidate.addedTokens.length + candidate.removedTokens.length;
  if (candidate.basis !== "direct" || size === 0) return [];
  const bonus = Math.max(0, 10 - Math.floor(Math.log2(1 + size)));
  return bonus > 0
    ? [{ points: bonus, reason: `small change (${size} identifiers or literals differ)` }]
    : [];
}

function namesInText(symbol: string, text: string): boolean {
  if (symbol.length < 3 || STOP_WORDS.has(symbol.toLowerCase())) return false;
  const escaped = symbol.replaceAll(/[$]/g, String.raw`\$`);
  return new RegExp(String.raw`(?<![\w$])${escaped}(?![\w$])`).test(text);
}

/** Points for the symbol or the added identifiers appearing in the advisory text. */
function textPoints(
  candidate: ScoredCandidate,
  hints: AdvisoryHints | undefined,
  hintWords: Set<string>,
): Points[] {
  if (!hints?.text) return [];
  const result: Points[] = [];
  if (namesInText(candidate.symbol, hints.text)) {
    result.push({ points: 60, reason: `\`${candidate.symbol}\` is named in the advisory text` });
  }
  const overlap = candidate.addedTokens
    .filter(
      (token) =>
        /^[A-Za-z_$][\w$]{3,}$/.test(token) &&
        !STOP_WORDS.has(token.toLowerCase()) &&
        hintWords.has(token.toLowerCase()),
    )
    .slice(0, 3);
  if (overlap.length > 0) {
    const named = overlap.map((token) => `\`${token}\``).join(", ");
    result.push({
      points: 10 * overlap.length,
      reason: `fix adds ${named}, which the advisory text mentions`,
    });
  }
  return result;
}

/** Points for added tokens that are typical of the fix for the advisory's weakness classes. */
function cwePoints(candidate: ScoredCandidate, cweIds: number[]): Points[] {
  if (cweIds.length === 0) return [];
  const matchedLabels: string[] = [];
  const matchedTokens = new Set<string>();
  for (const hint of CWE_HINTS) {
    if (!hint.ids.some((id) => cweIds.includes(id))) continue;
    const matches = candidate.addedTokens.filter((token) => hint.matches(token));
    if (matches.length > 0) {
      matchedLabels.push(hint.label);
      for (const token of matches.slice(0, 3)) matchedTokens.add(token);
    }
  }
  if (matchedTokens.size === 0) return [];
  const tokens = [...matchedTokens].map((token) => `\`${token}\``).join(", ");
  return [
    {
      points: Math.min(48, 12 * matchedTokens.size),
      reason: `fix adds ${tokens}, typical of ${matchedLabels.join(" and ")} (CWE ${cweIds.join(", ")})`,
    },
  ];
}

export function scoreCandidate(
  candidate: ScoredCandidate,
  depth: number,
  hints: AdvisoryHints | undefined,
  hintWords: Set<string>,
  cweIds: number[],
): { score: number; reasons: string[] } {
  const parts = [
    basisPoints(candidate, depth),
    ...sizePoints(candidate),
    ...textPoints(candidate, hints, hintWords),
    ...cwePoints(candidate, cweIds),
  ];
  return {
    score: parts.reduce((total, part) => total + part.points, 0),
    reasons: parts.map((part) => `${part.points >= 0 ? "+" : ""}${part.points} ${part.reason}`),
  };
}

export function topTokens(tokens: string[]): string[] {
  // Longer, identifier-like tokens first: they say more than punctuation-sized literals.
  return tokens.toSorted((a, b) => b.length - a.length || a.localeCompare(b)).slice(0, 12);
}
