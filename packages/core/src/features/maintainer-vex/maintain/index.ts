import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

import { assess } from "./assess.js";
import { applyChanges, formatChanges, pendingChanges, planChanges } from "./changes.js";
import { defaultDeps, type MaintainDeps } from "./deps.js";
import { readManifest } from "./manifest.js";
import { nextVersionOf } from "./package-files.js";
import { loadProjectLocks } from "./scope.js";
import type { MaintainAdvisory, MaintainOptions, MaintainResult } from "./types.js";

export type {
  MaintainAdvisory,
  MaintainDecision,
  MaintainOptions,
  MaintainPackageFinding,
  MaintainPlanSummary,
  MaintainResult,
} from "./types.js";
export type { MaintainDeps } from "./deps.js";
export { filesCover } from "./package-files.js";

const ADVISORY_ID = /^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/i;

/** The implementation with its outside world injectable. Use {@link maintain}. */
export async function maintainWith(
  deps: MaintainDeps,
  options: MaintainOptions = {},
): Promise<MaintainResult> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const manifest = readManifest(cwd);
  const notes: string[] = [];

  const ids = await resolveAdvisoryIds(deps, options, cwd);

  const locks = loadProjectLocks(cwd);
  notes.push(...locks.notes);

  const advisories: MaintainAdvisory[] = [];
  for (const id of ids.toSorted()) advisories.push(await assess(id, options, cwd, locks, deps));

  const usesChangesets = existsSync(join(cwd, ".changeset", "config.json"));
  const next = nextVersionOf(
    cwd,
    manifest.name,
    manifest.version,
    options.nextVersion,
    usesChangesets,
  );
  if (next.note) notes.push(next.note);

  const changes = planChanges({
    cwd,
    manifest,
    nextVersion: next.version,
    advisories,
    usesChangesets,
    now: () => deps.now(),
    notes,
  });
  const pending = pendingChanges(changes);
  const applied = options.yes ? applyChanges(cwd, changes) : false;

  return {
    schemaVersion: "1.0",
    cwd,
    package: { name: manifest.name, version: manifest.version, private: manifest.private },
    ...(next.version ? { nextVersion: next.version } : {}),
    usesChangesets,
    advisories,
    changes: formatChanges(changes),
    drift: pending.length > 0,
    applied,
    conflicts: changes
      .filter((change) => change.action === "conflict")
      .map((change) => change.path),
    notes,
  };
}

/**
 * For package authors: when a dependency of the package you are developing gets an advisory, decide
 * whether your package is affected (reachability from your source, plus a runtime trace when given)
 * and prepare, never publish or push: a bump plan, a changeset when the repository uses them, and
 * an OpenVEX statement shipped in the package (`package.json#vex`). Nothing is written without `yes`.
 */
export function maintain(options: MaintainOptions = {}): Promise<MaintainResult> {
  return maintainWith(defaultDeps, options);
}

async function resolveAdvisoryIds(
  deps: MaintainDeps,
  options: MaintainOptions,
  cwd: string,
): Promise<string[]> {
  if (!options.advisories || options.advisories.length === 0) {
    return deps.findAdvisories(cwd, options);
  }
  const bad = options.advisories.filter((id) => !ADVISORY_ID.test(id));
  if (bad.length > 0) throw new Error(`Not a CVE or GHSA id: ${bad.join(", ")}`);
  return [...new Set(options.advisories.map((id) => id.toUpperCase()))];
}
