/**
 * Why an export that exists in both versions is a fix-diff candidate: its own definition
 * changed, a function it calls changed, or a module it imports changed.
 */
import type { AdvisoryHints, CandidateBasis } from "./fix-diff.js";
import { tokenDelta } from "./fix-score.js";
import type { LocalDef } from "./js-exports.js";
import { type PackageIndex, type ResolvedExport } from "./package-index.js";

const MAX_VIA_DEPTH = 4;

export interface LocalChange {
  change: "changed" | "added" | "removed";
  oldDef?: LocalDef;
  newDef?: LocalDef;
}

/** What the comparison of one pair of versions shares between its steps. */
export interface Comparison {
  oldIndex: PackageIndex;
  newIndex: PackageIndex;
  hints: AdvisoryHints | undefined;
  hintWords: Set<string>;
  cweIds: number[];
  /** Definitions, `file#name`, that an export's change already accounts for. */
  explained: Set<string>;
  changedLocalsOf(
    oldFile: string | undefined,
    newFile: string | undefined,
  ): Map<string, LocalChange>;
}

/** The local definitions of a file that were added, removed or changed between the versions. */
export function createChangedLocals(oldIndex: PackageIndex, newIndex: PackageIndex) {
  const cache = new Map<string, Map<string, LocalChange>>();
  return (oldFile: string | undefined, newFile: string | undefined): Map<string, LocalChange> => {
    const key = `${oldFile ?? ""}|${newFile ?? ""}`;
    const cached = cache.get(key);
    if (cached) return cached;
    const result = new Map<string, LocalChange>();
    const oldLocals =
      (oldFile ? oldIndex.module(oldFile) : undefined)?.locals ?? new Map<string, LocalDef>();
    const newLocals =
      (newFile ? newIndex.module(newFile) : undefined)?.locals ?? new Map<string, LocalDef>();
    for (const [name, def] of newLocals) {
      const previous = oldLocals.get(name);
      if (!previous) result.set(name, { change: "added", newDef: def });
      else if (previous.fingerprint !== def.fingerprint) {
        result.set(name, { change: "changed", oldDef: previous, newDef: def });
      }
    }
    for (const [name, def] of oldLocals) {
      if (!newLocals.has(name)) result.set(name, { change: "removed", oldDef: def });
    }
    cache.set(key, result);
    return result;
  };
}

export type Basis = {
  basis: CandidateBasis;
  depth: number;
  via: string[];
  delta: { added: string[]; removed: string[] };
};

const NO_DELTA = (): Basis["delta"] => ({ added: [], removed: [] });

/** An export whose own definition differs between the versions. */
function directChange(ctx: Comparison, before: ResolvedExport, after: ResolvedExport) {
  if (after.kind === "module") {
    // `exports.x = require("./x")`: it is the required module that changed.
    return {
      basis: "via-internal-module",
      depth: 0,
      via: [after.moduleRef ?? after.definedIn],
      delta: NO_DELTA(),
    } satisfies Basis;
  }
  const delta = tokenDelta(before.tokens, after.tokens);
  if (after.local) ctx.explained.add(`${after.definedIn}#${after.local}`);
  // A bumped version constant is not a fix.
  const changedTokens = [...delta.added, ...delta.removed];
  if (changedTokens.length > 0 && changedTokens.every((token) => /^\d+\.\d+\.\d+/.test(token))) {
    return undefined;
  }
  return { basis: "direct", depth: 0, via: [], delta } satisfies Basis;
}

/** Breadth-first through the definitions an unchanged export refers to, in its own module. */
function internalFunctionChange(
  ctx: Comparison,
  before: ResolvedExport,
  after: ResolvedExport,
): Basis | undefined {
  const localChanges = ctx.changedLocalsOf(before.definedIn, after.definedIn);
  const module = ctx.newIndex.module(after.definedIn);
  const visited = new Set<string>();
  let frontier = [...after.refs].filter((ref) => module?.locals.has(ref));
  for (let level = 1; level <= MAX_VIA_DEPTH && frontier.length > 0; level++) {
    const next: string[] = [];
    const hits: string[] = [];
    for (const name of frontier.toSorted()) {
      if (visited.has(name)) continue;
      visited.add(name);
      if (localChanges.has(name)) hits.push(name);
      for (const ref of module?.locals.get(name)?.refs ?? []) {
        if (module?.locals.has(ref) && !visited.has(ref)) next.push(ref);
      }
    }
    if (hits.length > 0) {
      const delta = NO_DELTA();
      for (const name of hits) {
        ctx.explained.add(`${after.definedIn}#${name}`);
        const change = localChanges.get(name);
        if (!change) continue;
        const part = tokenDelta(
          change.oldDef?.tokens ?? new Set(),
          change.newDef?.tokens ?? new Set(),
        );
        delta.added.push(...part.added);
        delta.removed.push(...part.removed);
      }
      return { basis: "via-internal-function", depth: level, via: hits.slice(0, 3), delta };
    }
    frontier = next;
  }
  return undefined;
}

/** An unchanged export whose module imports a module that changed. */
function internalModuleChange(
  ctx: Comparison,
  before: ResolvedExport,
  after: ResolvedExport,
): Basis | undefined {
  const { oldIndex, newIndex } = ctx;
  if (!oldIndex.module(before.definedIn)) return undefined;
  for (const relative of newIndex.module(after.definedIn)?.relativeImports ?? []) {
    const newTarget = newIndex.resolveRelative(after.definedIn, relative);
    const oldTarget = oldIndex.resolveRelative(before.definedIn, relative);
    if (!newTarget || !oldTarget) continue;
    if (oldIndex.module(oldTarget)?.fingerprint !== newIndex.module(newTarget)?.fingerprint) {
      return { basis: "via-internal-module", depth: 0, via: [newTarget], delta: NO_DELTA() };
    }
  }
  return undefined;
}

/** Why an export that exists in both versions is a candidate, if it is one. */
export function basisOfChange(ctx: Comparison, before: ResolvedExport, after: ResolvedExport) {
  if (before.fingerprint !== after.fingerprint) return directChange(ctx, before, after);
  return internalFunctionChange(ctx, before, after) ?? internalModuleChange(ctx, before, after);
}
