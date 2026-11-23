/**
 * Fix-diff vulnerable symbols.
 *
 * Compare a vulnerable version of a package with the version that fixes it and list the exports
 * whose implementation changed. This is a HEURISTIC: a vulnerability fix changes the vulnerable
 * code, but a changed export is not proof it was the vulnerable one (refactors, helper changes and
 * unrelated fixes shipped in the same release show up too). Candidates are ranked, and when an
 * advisory text or CWE ids are given, by how closely the change matches them. Nothing here is
 * looked up or invented: every reason comes from the two versions' code or the text provided.
 */
import { basename } from "node:path";

import { basisOfChange, createChangedLocals, type Basis, type Comparison } from "./fix-changes.js";
import { parseCweIds, scoreCandidate, topTokens, wordsOf } from "./fix-score.js";
import { PackageIndex, specifierFor, type ResolvedExport } from "./package-index.js";
import type { PackageSource } from "./types.js";

export interface AdvisoryHints {
  /** Advisory summary and details, as free text. */
  text?: string;
  /** CWE identifiers (`CWE-1333` or `1333`). */
  cwes?: string[];
}

export type CandidateBasis =
  | "direct"
  | "removed-in-fix"
  | "via-internal-function"
  | "via-internal-module";

export interface VulnerableSymbolCandidate {
  /** Name to look for in project code (for a default export of a deep file, the file's name). */
  symbol: string;
  /** The export it is, `default` and `module.exports` included. */
  exportName: string;
  /** Import specifier that reaches it, e.g. `lodash` or `lodash/template`. */
  specifier: string;
  /** Other specifiers that reach the same definition. */
  alsoImportableAs?: string[];
  /** Defining file in the fixed version (the vulnerable version for a removed export). */
  file: string;
  kind: "function" | "class" | "value" | "module";
  basis: CandidateBasis;
  /** Changed internal functions or modules this export depends on (not for `direct`). */
  via: string[];
  score: number;
  /** Why it ranks where it does, one entry per contribution to the score. */
  reasons: string[];
  /** Identifiers and literals added by the fix and removed by it, most informative first. */
  addedTokens: string[];
  removedTokens: string[];
}

export interface ChangedInternal {
  file: string;
  name: string;
  change: "changed" | "added" | "removed";
}

export interface FixDiff {
  packageName: string;
  fromVersion: string;
  toVersion: string;
  /** Always true: the result is a heuristic, not a determination. */
  heuristic: true;
  candidates: VulnerableSymbolCandidate[];
  totalCandidates: number;
  /** Exports present only in the fixed version. */
  addedExports: string[];
  /** Files whose normalised content differs (formatting and comments ignored). */
  changedFiles: Array<{ file: string; change: "modified" | "added" | "removed" }>;
  /** Named internal definitions that changed and could not be tied to an export. */
  changedInternals: ChangedInternal[];
  /** What this analysis could not see, so a reader can judge a weak result. */
  limitations: string[];
}

export interface FindOptions {
  hints?: AdvisoryHints;
  /** Largest number of candidates returned (default 25). */
  limit?: number;
}

const DEFAULT_LIMIT = 25;
const MAX_DEEP_FILES = 1500;
const SKIPPED_DIRECTORIES =
  /(^|\/)(test|tests|__tests__|spec|specs|fixtures|examples?|docs?|benchmarks?|scripts)\//;

interface PublicModule {
  specifier: string;
  file: string;
}

/** Modules a consumer can import, keyed by specifier. */
function publicModules(index: PackageIndex): PublicModule[] {
  const manifestName = index.source.manifest.name;
  const name = typeof manifestName === "string" ? manifestName : index.source.name;
  const modules = new Map<string, PublicModule>();
  for (const entry of index.entries) {
    if (entry.file) {
      modules.set(specifierFor(name, entry.subpath), {
        specifier: specifierFor(name, entry.subpath),
        file: entry.file,
      });
    }
  }
  const hasExportsMap =
    index.source.manifest.exports !== undefined && index.source.manifest.exports !== null;
  if (!hasExportsMap) {
    const covered = new Set([...modules.values()].map((module) => module.file));
    let count = 0;
    for (const file of index.source.files.keys()) {
      if (covered.has(file) || /\.d\.[cm]?ts$/.test(file) || SKIPPED_DIRECTORIES.test(file)) {
        continue;
      }
      if (++count > MAX_DEEP_FILES) break;
      const stripped = file.replace(/\.[cm]?[jt]sx?$/, "");
      modules.set(`${name}/${stripped}`, { specifier: `${name}/${stripped}`, file });
    }
  }
  return [...modules.values()].toSorted((a, b) => a.specifier.localeCompare(b.specifier));
}

function isDefaultExport(exportName: string): boolean {
  return exportName === "default" || exportName === "module.exports";
}

/** The name to look for in project code: a deep file's default export is named by its file. */
function symbolFor(specifier: string, exportName: string, file: string): string {
  return isDefaultExport(exportName) && specifier.includes("/")
    ? basename(file).replace(/\.[cm]?[jt]sx?$/, "")
    : exportName;
}

function candidateFor(
  ctx: Comparison,
  where: { specifier: string; exportName: string },
  found: Basis,
  after: ResolvedExport,
): VulnerableSymbolCandidate {
  const base = {
    symbol: symbolFor(where.specifier, where.exportName, after.definedIn),
    exportName: where.exportName,
    specifier: where.specifier,
    file: after.definedIn,
    kind: after.kind,
    basis: found.basis,
    via: found.via,
    addedTokens: topTokens([...new Set(found.delta.added)]),
    removedTokens: topTokens([...new Set(found.delta.removed)]),
  };
  const { score, reasons } = scoreCandidate(
    base,
    found.depth,
    ctx.hints,
    ctx.hintWords,
    ctx.cweIds,
  );
  return { ...base, score, reasons };
}

function removedCandidate(
  ctx: Comparison,
  where: { specifier: string; exportName: string },
  before: ResolvedExport,
): VulnerableSymbolCandidate {
  const base = {
    symbol: symbolFor(where.specifier, where.exportName, before.definedIn),
    exportName: where.exportName,
    specifier: where.specifier,
    file: before.definedIn,
    kind: before.kind,
    basis: "removed-in-fix" as const,
    via: [] as string[],
    addedTokens: [] as string[],
    removedTokens: topTokens([...before.tokens]),
  };
  const { score, reasons } = scoreCandidate(base, 0, ctx.hints, ctx.hintWords, ctx.cweIds);
  return { ...base, score, reasons };
}

/** The candidates among the exports of every public module, and the exports that are new. */
function collectCandidates(
  ctx: Comparison,
  oldModules: Map<string, PublicModule>,
  newModules: Map<string, PublicModule>,
) {
  const candidates: VulnerableSymbolCandidate[] = [];
  const addedExports: string[] = [];
  let weakDiscovery = false;
  const specifiers = [...new Set([...oldModules.keys(), ...newModules.keys()])].toSorted();

  for (const specifier of specifiers) {
    const oldModule = oldModules.get(specifier);
    const newModule = newModules.get(specifier);
    const oldExports = oldModule
      ? ctx.oldIndex.exportsOf(oldModule.file)
      : new Map<string, ResolvedExport>();
    const newExports = newModule
      ? ctx.newIndex.exportsOf(newModule.file)
      : new Map<string, ResolvedExport>();
    if (newModule && ctx.newIndex.module(newModule.file)?.discovery === "namespace-assignments") {
      weakDiscovery = true;
    }

    for (const exportName of [
      ...new Set([...oldExports.keys(), ...newExports.keys()]),
    ].toSorted()) {
      const before = oldExports.get(exportName);
      const after = newExports.get(exportName);
      const where = { specifier, exportName };
      if (!after) {
        if (before) candidates.push(removedCandidate(ctx, where, before));
      } else if (before) {
        const found = basisOfChange(ctx, before, after);
        if (found) candidates.push(candidateFor(ctx, where, found, after));
      } else {
        addedExports.push(isDefaultExport(exportName) ? specifier : `${specifier}#${exportName}`);
      }
    }
  }
  return { candidates, addedExports, weakDiscovery };
}

/**
 * One entry per definition: the same export reached through several specifiers (`lodash` and
 * `lodash/index`) is listed once, under the shortest specifier, best score first.
 */
function rankCandidates(candidates: VulnerableSymbolCandidate[]): VulnerableSymbolCandidate[] {
  const byDefinition = new Map<string, VulnerableSymbolCandidate>();
  for (const candidate of candidates.toSorted(
    (a, b) => a.specifier.length - b.specifier.length || a.specifier.localeCompare(b.specifier),
  )) {
    const key = `${candidate.file}|${candidate.exportName}|${candidate.basis}`;
    const existing = byDefinition.get(key);
    if (existing) {
      existing.alsoImportableAs = [...(existing.alsoImportableAs ?? []), candidate.specifier];
      // A deep specifier names the file, which says more than `default` does.
      if (existing.symbol === existing.exportName && candidate.symbol !== candidate.exportName) {
        existing.symbol = candidate.symbol;
      }
    } else {
      byDefinition.set(key, { ...candidate });
    }
  }
  return [...byDefinition.values()].toSorted(
    (a, b) =>
      b.score - a.score ||
      a.specifier.localeCompare(b.specifier) ||
      a.symbol.localeCompare(b.symbol),
  );
}

/** Changed definitions no export could be tied to, and every file that differs at all. */
function summarizeChanges(ctx: Comparison, vulnerable: PackageSource, fixed: PackageSource) {
  const changedInternals: ChangedInternal[] = [];
  const changedFiles: FixDiff["changedFiles"] = [];
  const seenInternals = new Set<string>();
  const allFiles = [...new Set([...vulnerable.files.keys(), ...fixed.files.keys()])]
    .filter((file) => !/\.d\.[cm]?ts$/.test(file))
    .toSorted();
  for (const file of allFiles) {
    const inOld = vulnerable.files.has(file);
    const inNew = fixed.files.has(file);
    if (!inOld || !inNew) {
      changedFiles.push({ file, change: inNew ? "added" : "removed" });
      continue;
    }
    const oldMod = ctx.oldIndex.module(file);
    const newMod = ctx.newIndex.module(file);
    const differs =
      oldMod && newMod
        ? oldMod.fingerprint !== newMod.fingerprint
        : vulnerable.files.get(file) !== fixed.files.get(file);
    if (!differs) continue;
    changedFiles.push({ file, change: "modified" });
    for (const [name, change] of ctx.changedLocalsOf(file, file)) {
      const key = `${file}#${name}`;
      if (ctx.explained.has(key) || seenInternals.has(key)) continue;
      seenInternals.add(key);
      changedInternals.push({ file, name, change: change.change });
    }
  }
  return { changedInternals, changedFiles };
}

/** What this analysis could not see, so a reader can judge a weak result. */
function limitationsOf(
  found: { candidates: number; weakDiscovery: boolean; changedFiles: number },
  vulnerable: PackageSource,
  fixed: PackageSource,
): string[] {
  const limitations = [
    "Heuristic: a changed export is a candidate, not proof it was the vulnerable one.",
    "Static analysis of JavaScript source only; dynamically built exports, native addons and WebAssembly are not seen.",
  ];
  if (found.weakDiscovery) {
    limitations.push(
      "A bundle's exports were found by a namespace-assignment heuristic (`ns.name = fn`), so some exports may be missed or mis-attributed.",
    );
  }
  if (!vulnerable.integrityVerified || !fixed.integrityVerified) {
    limitations.push("At least one tarball had no registry digest to verify against.");
  }
  if (found.candidates === 0) {
    limitations.push(
      found.changedFiles === 0
        ? "The two versions' code is identical after normalising formatting and comments."
        : "Code changed, but no export could be tied to the change; see changedInternals.",
    );
  }
  return limitations;
}

function modulesByName(index: PackageIndex): Map<string, PublicModule> {
  return new Map(publicModules(index).map((module) => [module.specifier, module]));
}

/** Compare two versions of a package and rank the exports the fix changed. */
export function findVulnerableSymbols(
  vulnerable: PackageSource,
  fixed: PackageSource,
  options: FindOptions = {},
): FixDiff {
  const oldIndex = new PackageIndex(vulnerable);
  const newIndex = new PackageIndex(fixed);
  const hints = options.hints;
  const ctx: Comparison = {
    oldIndex,
    newIndex,
    hints,
    hintWords: wordsOf(hints?.text ?? ""),
    cweIds: parseCweIds(hints?.cwes, hints?.text),
    explained: new Set(),
    changedLocalsOf: createChangedLocals(oldIndex, newIndex),
  };
  const found = collectCandidates(ctx, modulesByName(oldIndex), modulesByName(newIndex));
  const ranked = rankCandidates(found.candidates);
  const { changedInternals, changedFiles } = summarizeChanges(ctx, vulnerable, fixed);

  const limit = Math.max(1, options.limit ?? DEFAULT_LIMIT);
  return {
    packageName: fixed.name,
    fromVersion: vulnerable.version,
    toVersion: fixed.version,
    heuristic: true,
    candidates: ranked.slice(0, limit),
    totalCandidates: ranked.length,
    addedExports: found.addedExports.toSorted().slice(0, 100),
    changedFiles: changedFiles.slice(0, 200),
    changedInternals: changedInternals.slice(0, 100),
    limitations: limitationsOf(
      {
        candidates: found.candidates.length,
        weakDiscovery: found.weakDiscovery,
        changedFiles: changedFiles.length,
      },
      vulnerable,
      fixed,
    ),
  };
}
