/**
 * Upgrade impact: how likely moving a package from one version to another is to break THIS project.
 *
 * Two inputs are combined. The package's changes between the versions (public API from declaration
 * files, falling back to JavaScript exports; `engines`, module format, `exports` map, peers) and
 * the project's usage of the package (which exports and members its source touches, and where).
 * A change counts only through the project code it reaches, and every finding carries the file and
 * line of that code. The rating is a fixed table of points (see `IMPACT_POINTS`), not a model.
 */
import { compareSurfaces, type ApiChange, type ChangeSeverity } from "./api-diff.js";
import { intersectApiChange } from "./api-reach.js";
import { extractDtsSurface, extractJsSurface, type ApiSurface } from "./dts-surface.js";
import {
  type Breakability,
  IMPACT_POINTS,
  type ImpactFinding,
  MEDIUM_THRESHOLD,
  packageChangeFinding,
  rate,
  summarize,
  toFinding,
} from "./findings.js";
import { comparePackageManifests, isSubpathExported } from "./manifest-diff.js";
import { PackageIndex, specifierFor, type EntryPoint } from "./package-index.js";
import type { PackageSource } from "./types.js";
import type { UsageIndex } from "./usage-index.js";

export interface UpgradeImpact {
  packageName: string;
  fromVersion: string;
  toVersion: string;
  breakability: Breakability;
  score: number;
  summary: string;
  findings: ImpactFinding[];
  /** Changes the project's code does not reach: not scored, but counted. */
  unreachedChanges: { breaking: number; possiblyBreaking: number };
  usage: {
    filesScanned: number;
    filesUsingPackage: number;
    specifiers: string[];
  };
  surface: {
    source: "types" | "js";
    entryPointsCompared: number;
    apiChanges: number;
  };
  limitations: string[];
  scoring: {
    points: typeof IMPACT_POINTS;
    mediumThreshold: number;
    rule: string;
  };
}

const MAX_FINDINGS = 100;
const MAX_ENTRIES_COMPARED = 60;

const SCORING_RULE =
  "High if any finding is a breaking change reached by project code (project-usage) or a conflict with the project's own manifest (project-conflict); otherwise Medium if the points total is at least the Medium threshold; otherwise Low.";

function pseudoEntry(index: PackageIndex, subpath: string): EntryPoint | undefined {
  const known = index.entries.find((entry) => entry.subpath === subpath);
  if (known) return known;
  if (index.source.manifest.exports !== undefined && index.source.manifest.exports !== null) {
    return undefined;
  }
  const relative = subpath.replace(/^\.\//, "");
  const file = index.resolveRelative("package.json", `./${relative}`);
  const base = relative.replace(/\.[cm]?js$/, "");
  const typesFile = [`${base}.d.ts`, `${base}/index.d.ts`].find((candidate) =>
    index.hasFile(candidate),
  );
  return file || typesFile ? { subpath, file, typesFile } : undefined;
}

function surfacesFor(
  before: PackageIndex,
  after: PackageIndex,
  oldEntry: EntryPoint,
  newEntry: EntryPoint,
): { before: ApiSurface; after: ApiSurface } | undefined {
  if (oldEntry.typesFile !== undefined && newEntry.typesFile !== undefined) {
    return {
      before: extractDtsSurface(before, oldEntry.typesFile),
      after: extractDtsSurface(after, newEntry.typesFile),
    };
  }
  if (oldEntry.file && newEntry.file) {
    return {
      before: extractJsSurface(before, oldEntry.file),
      after: extractJsSurface(after, newEntry.file),
    };
  }
  return undefined;
}

export interface AnalyzeUpgradeInput {
  before: PackageSource;
  after: PackageSource;
  usage: UsageIndex;
  /** The project's own `package.json`, when there is one. */
  projectManifest?: Record<string, unknown>;
  runtimeNode?: string;
}

/** What the steps of an analysis collect as they go. */
interface Analysis {
  findings: ImpactFinding[];
  unreached: { breaking: number; possiblyBreaking: number };
  apiChanges: ApiChange[];
  notes: Set<string>;
  sourceKind: "types" | "js";
  compared: number;
}

function countUnreached(analysis: Analysis, severity: ChangeSeverity): void {
  if (severity === "breaking") analysis.unreached.breaking++;
  else analysis.unreached.possiblyBreaking++;
}

/** Which subpaths to compare: the root, whatever the project imports, then the rest up to a cap. */
function subpathsToCompare(
  packageName: string,
  usage: UsageIndex,
  oldIndex: PackageIndex,
  newIndex: PackageIndex,
): string[] {
  const usedSubpaths = [...usage.specifiers]
    .filter((specifier) => specifier.startsWith(`${packageName}/`))
    .map((specifier) => `./${specifier.slice(packageName.length + 1)}`);
  return [
    ...new Set([
      ".",
      ...usedSubpaths,
      ...oldIndex.entries.map((entry) => entry.subpath),
      ...newIndex.entries.map((entry) => entry.subpath),
    ]),
  ].slice(0, MAX_ENTRIES_COMPARED + usedSubpaths.length);
}

/** Compares the API of every entry point both versions share, and notes the ones that vanished. */
function compareEntryPoints(
  input: AnalyzeUpgradeInput,
  indexes: { before: PackageIndex; after: PackageIndex },
  analysis: Analysis,
): void {
  const { after, usage } = input;
  const packageName = after.name;
  for (const subpath of subpathsToCompare(packageName, usage, indexes.before, indexes.after)) {
    const specifier = specifierFor(packageName, subpath);
    const oldEntry = pseudoEntry(indexes.before, subpath);
    const newEntry = pseudoEntry(indexes.after, subpath);
    if (oldEntry && !newEntry) {
      // The module was reachable before and is not now. With an `exports` map the package-level
      // comparison reports it, so it is not reported twice.
      if (after.manifest.exports !== undefined && after.manifest.exports !== null) continue;
      if (usage.specifiers.has(specifier)) {
        analysis.findings.push(removedSubpathFinding(specifier, subpath, after, usage));
      } else {
        countUnreached(analysis, "breaking");
      }
      continue;
    }
    if (!oldEntry || !newEntry) continue;
    const surfaces = surfacesFor(indexes.before, indexes.after, oldEntry, newEntry);
    if (!surfaces) continue;
    analysis.compared++;
    if (surfaces.before.source === "types") analysis.sourceKind = "types";
    for (const note of [...surfaces.before.notes, ...surfaces.after.notes]) {
      analysis.notes.add(note);
    }
    analysis.apiChanges.push(...compareSurfaces(specifier, surfaces.before, surfaces.after));
  }
}

function removedSubpathFinding(
  specifier: string,
  subpath: string,
  after: PackageSource,
  usage: UsageIndex,
): ImpactFinding {
  const exported = isSubpathExported(after.manifest, subpath) ? "" : " or no longer exported";
  return toFinding(
    {
      scope: "package",
      category: "removed-subpath",
      severity: "breaking",
      evidence: "project-usage",
      specifier,
      reason: `\`${specifier}\` can no longer be imported: ${subpath} is gone from the package${exported}`,
    },
    usage.importSites.get(specifier) ?? [],
  );
}

/** Turns each API change into a finding when project code reaches it; counts the rest. */
function reachApiChanges(usage: UsageIndex, analysis: Analysis): void {
  let opaqueBreaking = 0;
  for (const change of analysis.apiChanges) {
    const reach = intersectApiChange(change, usage);
    if (reach.sites.length === 0) {
      if (
        !reach.compatible &&
        (usage.opaque.get(change.specifier)?.length ?? 0) > 0 &&
        change.severity === "breaking"
      ) {
        opaqueBreaking++;
      }
      countUnreached(analysis, change.severity);
      continue;
    }
    analysis.findings.push(
      toFinding(
        {
          scope: "api",
          category: change.category,
          severity: change.severity,
          evidence: reach.evidence,
          specifier: change.specifier,
          symbol: change.symbol,
          member: change.member,
          reason: change.reason,
          before: change.before,
          after: change.after,
        },
        reach.sites,
      ),
    );
  }
  // The module object is used in ways we cannot follow, and the package has breaking changes.
  if (opaqueBreaking > 0) {
    const sites = [...usage.opaque.keys()].toSorted().flatMap((key) => usage.opaque.get(key) ?? []);
    const plural = opaqueBreaking === 1 ? "" : "s";
    analysis.findings.push(
      toFinding(
        {
          scope: "api",
          category: "opaque-usage",
          severity: "possibly-breaking",
          evidence: "opaque-usage",
          reason: `the package object is used dynamically (passed along or accessed by computed name), so ${opaqueBreaking} breaking API change${plural} cannot be ruled out`,
        },
        sites,
      ),
    );
  }
}

/** Findings for `engines`, module format, `exports` and peer changes between the manifests. */
function reachPackageChanges(input: AnalyzeUpgradeInput, analysis: Analysis): void {
  const { before, after, usage, projectManifest } = input;
  const context = {
    usage,
    packageName: after.name,
    requireSites: [...usage.requireSites.values()].flat(),
    importSites: [...usage.importSites.values()].flat(),
    after,
  };
  const changes = comparePackageManifests(
    before.manifest,
    after.manifest,
    projectManifest,
    input.runtimeNode,
  );
  for (const change of changes) {
    const finding = packageChangeFinding(change, context);
    if (finding) analysis.findings.push(finding);
    else countUnreached(analysis, change.severity);
  }
}

/** What the analysis could not see, so a reader knows how far to trust a Low rating. */
function limitationsOf(input: AnalyzeUpgradeInput, analysis: Analysis): string[] {
  const { before, after, usage } = input;
  const limitations: string[] = [];
  if (usage.specifiers.size === 0) {
    limitations.push(
      `No source file in the project imports "${after.name}" directly. Usage through other packages that depend on it (transitive consumers) is not analysed, so only package-level findings can apply.`,
    );
  }
  if (usage.filesScanned === 0) limitations.push("No project source files were found to scan.");
  if (analysis.sourceKind === "js") {
    limitations.push(
      "No declaration files in both versions: the API was read from JavaScript exports, so parameter and return types are not compared. Types from @types packages are not consulted.",
    );
  }
  limitations.push(
    "Class and interface instance members are matched by member name only (no type information), so those findings are marked name-match and weigh less.",
    "Shadowed identifiers and aliasing through reassignment are not tracked.",
    ...analysis.notes,
  );
  if (!before.integrityVerified || !after.integrityVerified) {
    limitations.push("At least one tarball had no registry digest to verify against.");
  }
  return [...new Set(limitations)];
}

function sortFindings(findings: ImpactFinding[]): ImpactFinding[] {
  return findings
    .toSorted(
      (a, b) =>
        b.points - a.points ||
        (a.specifier ?? "").localeCompare(b.specifier ?? "") ||
        (a.symbol ?? "").localeCompare(b.symbol ?? "") ||
        (a.member ?? "").localeCompare(b.member ?? ""),
    )
    .slice(0, MAX_FINDINGS);
}

/** Pure analysis of an upgrade: no network, no file system. */
export function analyzeUpgrade(input: AnalyzeUpgradeInput): UpgradeImpact {
  const { before, after, usage } = input;
  const analysis: Analysis = {
    findings: [],
    unreached: { breaking: 0, possiblyBreaking: 0 },
    apiChanges: [],
    notes: new Set<string>(),
    sourceKind: "js",
    compared: 0,
  };

  compareEntryPoints(
    input,
    { before: new PackageIndex(before), after: new PackageIndex(after) },
    analysis,
  );
  reachApiChanges(usage, analysis);
  reachPackageChanges(input, analysis);

  const { findings, unreached } = analysis;
  const { score, breakability } = rate(findings);
  return {
    packageName: after.name,
    fromVersion: before.version,
    toVersion: after.version,
    breakability,
    score,
    summary: summarize(breakability, findings, unreached, usage.specifiers.size > 0),
    findings: sortFindings(findings),
    unreachedChanges: unreached,
    usage: {
      filesScanned: usage.filesScanned,
      filesUsingPackage: usage.filesUsingPackage,
      specifiers: [...usage.specifiers].toSorted(),
    },
    surface: {
      source: analysis.sourceKind,
      entryPointsCompared: analysis.compared,
      apiChanges: analysis.apiChanges.length,
    },
    limitations: limitationsOf(input, analysis),
    scoring: { points: IMPACT_POINTS, mediumThreshold: MEDIUM_THRESHOLD, rule: SCORING_RULE },
  };
}

export { IMPACT_POINTS, MEDIUM_THRESHOLD, rate } from "./findings.js";
export type { Breakability, FindingEvidence, ImpactFinding } from "./findings.js";
