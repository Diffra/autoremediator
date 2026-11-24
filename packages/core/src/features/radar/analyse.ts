/**
 * Radar's work on one installed package: pick a newer release, read what changed between the two
 * (changelog, code, registry metadata, optionally a model), score it, and cross-check OSV.
 */
import semver from "semver";

import { errorMessage } from "../../shared/errors.js";
import { classifyUpgradeLevel } from "../intelligence/sources/registry.js";
import { checkAdvisories } from "./advisories.js";
import { scoreWithModel } from "./model-review.js";
import { releaseNotesFlags, repositoryOf } from "./release-notes.js";
import type { Comparison, Outcome, Run } from "./run.js";
import { codeDiffFlags } from "./signals/code-diff.js";
import { metadataFlags } from "./signals/metadata.js";
import { sanitizeEvidence } from "./signals/sanitize.js";
import type { RadarScore } from "./signals/score.js";
import type { RadarFlag } from "./signals/types.js";
import { pickTarget } from "./target.js";
import type { InstalledPackage, RadarEntry, RadarPackage, RegistryVersions } from "./types.js";

/** Releases diffed one by one up to this many; beyond it installed and target are diffed once. */
const MAX_STEPWISE_RELEASES = 5;
const MAX_LISTED_RELEASES = 100;

type Loader = (name: string, version: string) => Promise<RadarPackage>;

export async function analyse(run: Run, installed: InstalledPackage): Promise<Outcome> {
  const { deps, cwd, budget } = run;
  const registry = await deps.fetchVersions(installed.name, cwd, budget);
  if (!registry || registry.versions.length === 0) {
    return {
      kind: "skipped",
      skipped: {
        name: installed.name,
        version: installed.version,
        reason: "not found on the registry",
      },
    };
  }
  const stable = registry.versions.map((entry) => entry.version);
  const target = pickTarget(installed.version, stable, registry.latest, run.options.target);
  if (!target) return { kind: "up-to-date" };
  const range = stable
    .filter((version) => semver.gt(version, installed.version) && semver.lte(version, target))
    .toSorted((a, b) => semver.compare(a, b));
  const upgrade = classifyUpgradeLevel(installed.version, target);
  if (!upgrade) return { kind: "up-to-date" };

  const load = createLoader(run);
  const notes: string[] = [];
  if (registry.note) notes.push(registry.note);

  const comparison = await loadComparison(load, installed, target, range);
  const { flags, filesChanged } = await collectFlags(run, comparison, registry.versions, notes);
  const scored = await scoreWithModel(deps, comparison, flags, notes);
  if (scored.confidence === undefined) return { kind: "clean" };

  const { status, advisories } = await checkAdvisories(
    deps,
    installed.name,
    installed.version,
    target,
    notes,
  );
  const entry: RadarEntry = {
    name: installed.name,
    installed: installed.version,
    target,
    upgrade,
    direct: installed.direct,
    scope: installed.scope,
    releases: range.slice(-MAX_LISTED_RELEASES),
    diff: comparison.diffMode,
    score: scored.score,
    confidence: scored.confidence,
    breakdown: scored.breakdown,
    status,
    advisories,
    statement:
      status === "now-advisory"
        ? `An advisory now covers this range (${advisories.map((advisory) => advisory.id).join(", ")}).`
        : "Security-relevant change without a published advisory. Not a statement that a vulnerability exists.",
    flags: flags.toSorted((a, b) => b.points - a.points || a.release.localeCompare(b.release)),
    notes,
  };
  addRangeNotes(entry, range.length, filesChanged);
  await assessImpact(run, installed, entry, scored, load);
  return { kind: "entry", entry };
}

/** Loads each package version once, however many steps ask for it. */
function createLoader(run: Run): Loader {
  const cache = new Map<string, Promise<RadarPackage>>();
  return (name, version) => {
    const key = `${name}@${version}`;
    const cached = cache.get(key);
    if (cached) return cached;
    const pending = run.deps.loadPackage(name, version, run.cwd, run.budget);
    cache.set(key, pending);
    return pending;
  };
}

async function loadComparison(
  load: Loader,
  installed: InstalledPackage,
  target: string,
  range: string[],
): Promise<Comparison> {
  const chain =
    range.length <= MAX_STEPWISE_RELEASES
      ? [installed.version, ...range]
      : [installed.version, target];
  const diffMode: RadarEntry["diff"] =
    range.length <= MAX_STEPWISE_RELEASES ? "per-release" : "span";
  const packages: RadarPackage[] = [];
  for (const version of chain) packages.push(await load(installed.name, version));
  return { name: installed.name, installed: installed.version, target, range, diffMode, packages };
}

/** Changelog, code and registry-metadata flags for the comparison, in that order. */
async function collectFlags(
  run: Run,
  comparison: Comparison,
  versions: RegistryVersions["versions"],
  notes: string[],
): Promise<{ flags: RadarFlag[]; filesChanged: number }> {
  const { installed, target } = comparison;
  const flags: RadarFlag[] = [];

  const after = comparison.packages.at(-1)!;
  const notesResult = await releaseNotesFlags(
    run,
    installed,
    target,
    comparison.range,
    after.docs,
    repositoryOf(after.manifest),
  );
  flags.push(...notesResult.flags);
  if (notesResult.note) run.notes.add(notesResult.note);
  if (!notesResult.found) {
    notes.push(
      run.options.github
        ? "no changelog for these releases in the package or on GitHub"
        : "no changelog for these releases in the package (pass github to read GitHub release notes)",
    );
  }

  const filesChanged = collectCodeFlags(comparison, flags, notes);
  flags.push(...metadataFlags(versions, installed, target));
  return { flags, filesChanged };
}

/** Code differences, release by release when there are few. Returns the files that changed. */
function collectCodeFlags(comparison: Comparison, flags: RadarFlag[], notes: string[]): number {
  const { packages, diffMode } = comparison;
  let filesChanged = 0;
  for (let index = 1; index < packages.length; index++) {
    const previous = packages[index - 1]!;
    const current = packages[index]!;
    const release =
      diffMode === "span" ? `${previous.version}..${current.version}` : current.version;
    const result = codeDiffFlags({ before: previous.files, after: current.files }, release);
    filesChanged += result.filesChanged;
    flags.push(...result.flags);
    if (result.filesSkipped > 0) {
      notes.push(
        `${result.filesSkipped} file(s) in ${release} were too large or unparseable and were not compared`,
      );
    }
  }
  if (diffMode === "span") {
    notes.push(
      `${comparison.range.length} releases in range: ${comparison.installed} and ${comparison.target} were compared once, so code signals are attributed to the span`,
    );
  }
  return filesChanged;
}

function addRangeNotes(entry: RadarEntry, releaseCount: number, filesChanged: number): void {
  if (releaseCount > MAX_LISTED_RELEASES) {
    entry.notes.push(
      `only the newest ${MAX_LISTED_RELEASES} of ${releaseCount} releases are listed`,
    );
  }
  if (filesChanged === 0 && entry.diff === "per-release") {
    entry.notes.push("no source file changed between these releases");
  }
}

/** Upgrade impact on this project, for the few best direct dependencies. */
async function assessImpact(
  run: Run,
  installed: InstalledPackage,
  entry: RadarEntry,
  scored: RadarScore,
  load: Loader,
): Promise<void> {
  if (
    !run.options.assess ||
    !installed.direct ||
    scored.confidence === "weak" ||
    run.assessRemaining.count <= 0
  ) {
    return;
  }
  run.assessRemaining.count--;
  try {
    const impact = await run.deps.assess(
      installed.name,
      installed.version,
      entry.target,
      run.cwd,
      load,
    );
    entry.impact = {
      rating: impact.breakability,
      summary: sanitizeEvidence(impact.summary, 200),
      findings: impact.findings.length,
    };
  } catch (error) {
    entry.notes.push(
      `upgrade impact could not be assessed (${sanitizeEvidence(errorMessage(error), 100)})`,
    );
  }
}
