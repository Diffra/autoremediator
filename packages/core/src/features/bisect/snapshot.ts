/**
 * Reads what changed between the two refs: finds the repository, resolves both commits, picks the
 * lockfile and compares it, so the search starts from a list of package updates.
 */
import { realpathSync } from "node:fs";
import { relative, resolve, sep } from "node:path";

import type { PackageManager } from "../../shared/types.js";
import { directDependencyNames, lockfileChanges, type ManifestLike } from "./changes.js";
import { git, resolveCommit, showAt } from "./refs.js";
import type { BisectedPackage, BisectOptions, BisectSkippedChange } from "./types.js";

/** Lockfile names in the order they are looked for, with the manager each one means. */
const LOCKFILES: ReadonlyArray<[file: string, manager: PackageManager]> = [
  ["pnpm-lock.yaml", "pnpm"],
  ["package-lock.json", "npm"],
  ["yarn.lock", "yarn"],
  ["bun.lock", "bun"],
  ["bun.lockb", "bun"],
];

export interface LockfileSnapshot {
  /** Project directory, absolute. */
  cwd: string;
  /** Root of the git repository. */
  top: string;
  /** The project's directory inside the repository, posix style; empty at the root. */
  sub: string;
  goodCommit: string;
  badCommit: string;
  manager: PackageManager;
  /** Lockfile compared, relative to the project directory. */
  lockfile: string;
  updates: BisectedPackage[];
  skipped: BisectSkippedChange[];
}

interface Repository {
  top: string;
  sub: string;
  /** The path of a project file inside the repository. */
  inRepo: (file: string) => string;
}

export async function readLockfileSnapshot(
  options: BisectOptions,
  badRef: string,
): Promise<LockfileSnapshot> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const repo = await locateRepository(cwd);
  const { top, sub, inRepo } = repo;

  const goodCommit = await resolveCommit(top, "good", options.good);
  const badCommit = await resolveCommit(top, "bad", badRef);
  if (goodCommit === badCommit) {
    throw new Error("good and bad are the same commit: there is nothing to bisect.");
  }

  const { lockfile, manager } = await findLockfile({ repo, badCommit, badRef, options });
  const { goodLock, badLock } = await readLockfiles({
    repo,
    lockfile,
    manager,
    goodCommit,
    badCommit,
    good: options.good,
    badRef,
  });
  const goodManifestText = await showAt(top, goodCommit, inRepo("package.json"));
  if (goodManifestText === undefined) {
    throw new Error(`package.json does not exist at ${options.good}.`);
  }
  const badManifest = parseManifest(await showAt(top, badCommit, inRepo("package.json")));

  const { updates, skipped } = lockfileChanges(
    lockfile,
    goodLock,
    badLock,
    directDependencyNames(badManifest),
  );
  return { cwd, top, sub, goodCommit, badCommit, manager, lockfile, updates, skipped };
}

async function locateRepository(cwd: string): Promise<Repository> {
  const top = (await git(cwd, ["rev-parse", "--show-toplevel"])).stdout.trim();
  if (!top) throw new Error("bisect needs a git repository: this directory is not one.");
  const sub = relative(realpathSync(top), realpathSync(cwd)).split(sep).join("/");
  return { top, sub, inRepo: (file) => (sub ? `${sub}/${file}` : file) };
}

/** Which lockfile, hence which package manager. */
async function findLockfile(input: {
  repo: Repository;
  badCommit: string;
  badRef: string;
  options: BisectOptions;
}): Promise<{ lockfile: string; manager: PackageManager }> {
  const { repo, badCommit, badRef, options } = input;
  let found: { lockfile: string; manager: PackageManager } | undefined;
  for (const [file, candidate] of LOCKFILES) {
    if (options.packageManager && candidate !== options.packageManager) continue;
    if ((await git(repo.top, ["cat-file", "-e", `${badCommit}:${repo.inRepo(file)}`])).ok) {
      found = { lockfile: file, manager: candidate };
      break;
    }
  }
  if (!found) {
    throw new Error(
      `No supported lockfile (${LOCKFILES.map(([file]) => file).join(", ")}) at ${badRef} in ${repo.sub || "the repository root"}.`,
    );
  }
  if (found.manager === "bun") {
    throw new Error(
      "bisect cannot read bun lockfiles yet; npm, pnpm and yarn (classic) are supported.",
    );
  }
  return found;
}

async function readLockfiles(input: {
  repo: Repository;
  lockfile: string;
  manager: PackageManager;
  goodCommit: string;
  badCommit: string;
  good: string;
  badRef: string;
}): Promise<{ goodLock: string; badLock: string }> {
  const { repo, lockfile, manager, goodCommit, badCommit, good, badRef } = input;
  const goodLock = await showAt(repo.top, goodCommit, repo.inRepo(lockfile));
  const badLock = await showAt(repo.top, badCommit, repo.inRepo(lockfile));
  if (goodLock === undefined) {
    throw new Error(
      `${lockfile} does not exist at ${good}: there is no lockfile to compare against.`,
    );
  }
  if (badLock === undefined) throw new Error(`${lockfile} does not exist at ${badRef}.`);
  if (manager === "yarn" && (goodLock.includes("__metadata:") || badLock.includes("__metadata:"))) {
    throw new Error("bisect reads yarn classic (v1) lockfiles only; this one is from yarn berry.");
  }
  return { goodLock, badLock };
}

function parseManifest(text: string | undefined): ManifestLike | undefined {
  if (text === undefined) return undefined;
  try {
    return JSON.parse(text) as ManifestLike;
  } catch {
    return undefined;
  }
}
