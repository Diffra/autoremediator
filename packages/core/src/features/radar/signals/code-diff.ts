/**
 * Code signals between two published versions of a package: what a fix for an injection, traversal,
 * prototype-pollution or ReDoS bug tends to add (a guard, a containment check, a length limit, a
 * sanitizer, a regular expression without nested quantifiers) or remove (an `eval`, a shell, an
 * `innerHTML` write). Found by walking the syntax tree of every file present in both versions, so
 * reformatting and comments do not count. A signal is something the new version has and the old one
 * did not (or the reverse for removed sinks), keyed by the normalised source text of the node.
 *
 * HEURISTIC. A guard can be added for a reason that has nothing to do with security. Each signal is
 * evidence for a human to read, never a statement that a vulnerability existed.
 */
import { parseFindings, type CodeSignal, type Finding } from "./code-patterns.js";
import { evidenceLine, sanitizeEvidence } from "./sanitize.js";
import { RADAR_POINTS, type RadarFlag } from "./types.js";

export { isRedosProne } from "./redos.js";

export interface FileVersions {
  before: ReadonlyMap<string, string>;
  after: ReadonlyMap<string, string>;
}

export interface CodeDiffResult {
  flags: RadarFlag[];
  filesCompared: number;
  filesChanged: number;
  /** Files skipped for size, count cap or parse failure. */
  filesSkipped: number;
}

interface Hit {
  signal: CodeSignal;
  file: string;
  line: number;
  snippet: string;
  key: string;
}

interface Tally {
  compared: number;
  changed: number;
  skipped: number;
}

const MAX_FILE_BYTES = 1_500_000;
const MAX_FILES = 400;

const SKIPPED_PATH =
  /(?:^|\/)(?:tests?|__tests__|specs?|examples?|benchmarks?|bench|fixtures?|docs?|coverage)\/|\.(?:test|spec)\.[cm]?[jt]sx?$|\.d\.[cm]?ts$|\.min\./i;

const REMOVAL_SIGNALS = new Set<CodeSignal>([
  "dangerous-sink-removed",
  "redos-regex-replaced",
  "regex-changed",
]);
const ADDITION_SIGNALS = new Set<CodeSignal>([
  "prototype-guard-added",
  "traversal-check-added",
  "path-containment-added",
  "timing-safe-compare-added",
  "sanitizer-added",
  "invalid-input-rejected",
  "own-property-check-added",
  "null-prototype-object-added",
  "length-limit-added",
  "validator-added",
]);

/**
 * Compare two versions' files and return what changed in security-relevant ways. `release` labels
 * the flags (a version, or a span when several releases were diffed at once).
 */
export function codeDiffFlags(versions: FileVersions, release: string): CodeDiffResult {
  const hits: Hit[] = [];
  const tally: Tally = { compared: 0, changed: 0, skipped: 0 };

  const paths = [...versions.after.keys()]
    .filter((path) => versions.before.has(path) && !SKIPPED_PATH.test(path))
    .toSorted();
  for (const path of paths) {
    const before = versions.before.get(path) ?? "";
    const after = versions.after.get(path) ?? "";
    hits.push(...compareFile(path, before, after, tally));
  }

  return {
    flags: toFlags(withContainmentPairs(hits), release),
    filesCompared: tally.compared,
    filesChanged: tally.changed,
    filesSkipped: tally.skipped,
  };
}

const meaningfulLines = (text: string): string[] =>
  text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(
      (line) =>
        line !== "" && !line.startsWith("//") && !line.startsWith("*") && !line.startsWith("/*"),
    );

/** Added and removed non-blank lines between two files (multiset difference), for a model to read. */
export function lineDiff(before: string, after: string): { added: string[]; removed: string[] } {
  const counts = new Map<string, number>();
  for (const line of meaningfulLines(before)) counts.set(line, (counts.get(line) ?? 0) + 1);
  const added: string[] = [];
  for (const line of meaningfulLines(after)) {
    const left = counts.get(line) ?? 0;
    if (left > 0) counts.set(line, left - 1);
    else added.push(line);
  }
  const removed: string[] = [];
  for (const [line, count] of counts)
    for (let index = 0; index < count; index++) removed.push(line);
  return { added, removed };
}

function findingId(finding: Finding): string {
  return `${finding.signal}\u0000${finding.key}`;
}

function multiset(findings: readonly Finding[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    const id = findingId(finding);
    counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  return counts;
}

/** The hits one file contributes, updating the tally of files compared, changed and skipped. */
function compareFile(path: string, before: string, after: string, tally: Tally): Hit[] {
  tally.compared++;
  if (before === after) return [];
  if (
    tally.changed >= MAX_FILES ||
    before.length > MAX_FILE_BYTES ||
    after.length > MAX_FILE_BYTES
  ) {
    tally.skipped++;
    return [];
  }
  tally.changed++;
  const was = parseFindings(path, before);
  const now = parseFindings(path, after);
  if (!was || !now) {
    tally.skipped++;
    return [];
  }
  const wasCounts = multiset(was);
  const nowCounts = multiset(now);
  return [
    ...additionHits(path, now, wasCounts),
    ...removalHits(path, was, now, wasCounts, nowCounts),
  ];
}

function additionHits(
  path: string,
  now: readonly Finding[],
  wasCounts: ReadonlyMap<string, number>,
): Hit[] {
  const hits: Hit[] = [];
  const spent = new Map<string, number>();
  for (const finding of now) {
    if (!ADDITION_SIGNALS.has(finding.signal)) continue;
    const id = findingId(finding);
    const used = (spent.get(id) ?? 0) + 1;
    spent.set(id, used);
    if (used > (wasCounts.get(id) ?? 0)) hits.push(toHit(finding, path));
  }
  return hits;
}

/** A replacement regex that is not itself ReDoS-prone, newly present in the new version. */
function findSafeReplacement(
  now: readonly Finding[],
  wasCounts: ReadonlyMap<string, number>,
  nowCounts: ReadonlyMap<string, number>,
): Finding | undefined {
  return now
    .filter(
      (finding) =>
        (finding.signal === "regex-changed" || finding.signal === "redos-regex-replaced") &&
        (nowCounts.get(findingId(finding)) ?? 0) > (wasCounts.get(findingId(finding)) ?? 0),
    )
    .find((finding) => finding.signal === "regex-changed");
}

/** Removals are read from the old version: report the line it had there. */
function removalHits(
  path: string,
  was: readonly Finding[],
  now: readonly Finding[],
  wasCounts: ReadonlyMap<string, number>,
  nowCounts: ReadonlyMap<string, number>,
): Hit[] {
  const safeReplacement = findSafeReplacement(now, wasCounts, nowCounts);
  const hits: Hit[] = [];
  const removedSpent = new Map<string, number>();
  for (const finding of was) {
    if (!REMOVAL_SIGNALS.has(finding.signal)) continue;
    const id = findingId(finding);
    const used = (removedSpent.get(id) ?? 0) + 1;
    removedSpent.set(id, used);
    if (used <= (nowCounts.get(id) ?? 0)) continue;
    hits.push(removalHit(finding, path, safeReplacement));
  }
  return hits;
}

function toHit(finding: Finding, file: string): Hit {
  return {
    signal: finding.signal,
    file,
    line: finding.line,
    snippet: finding.snippet,
    key: finding.key,
  };
}

function removalHit(finding: Finding, file: string, safeReplacement: Finding | undefined): Hit {
  if (finding.signal === "redos-regex-replaced") {
    return {
      signal: safeReplacement ? "redos-regex-replaced" : "redos-regex-removed",
      file,
      line: finding.line,
      snippet: `${finding.key}${safeReplacement ? ` -> ${safeReplacement.key}` : " (removed)"}`,
      key: finding.key,
    };
  }
  if (finding.signal === "regex-changed") {
    return {
      signal: "regex-changed",
      file,
      line: finding.line,
      snippet: finding.key,
      key: finding.key,
    };
  }
  return toHit(finding, file);
}

/** Path containment needs both halves in one file: a resolve/relative and a prefix check. */
function withContainmentPairs(hits: readonly Hit[]): Hit[] {
  const containment = hits.filter((hit) => hit.signal === "path-containment-added");
  const filesWithBoth = new Set(
    containment
      .filter((hit) => hit.key === "startsWith")
      .map((hit) => hit.file)
      .filter((file) =>
        containment.some((other) => other.file === file && other.key !== "startsWith"),
      ),
  );
  return hits.filter(
    (hit) => hit.signal !== "path-containment-added" || filesWithBoth.has(hit.file),
  );
}

/** One flag per signal, quoting the first occurrence and counting the rest. */
function toFlags(hits: readonly Hit[], release: string): RadarFlag[] {
  const bySignal = new Map<CodeSignal, Hit[]>();
  for (const hit of hits) bySignal.set(hit.signal, [...(bySignal.get(hit.signal) ?? []), hit]);

  const flags: RadarFlag[] = [];
  for (const [signal, group] of bySignal) {
    const first = group[0];
    if (!first) continue;
    flags.push({
      category: "code",
      signal,
      release,
      points: RADAR_POINTS.code[signal],
      location: sanitizeEvidence(`${first.file}:${first.line}`, 160),
      evidence: evidenceLine(`${first.file}:${first.line}`, first.snippet),
      occurrences: group.length,
    });
  }
  return flags.toSorted((a, b) => b.points - a.points || a.signal.localeCompare(b.signal));
}
