import { git, readBlobs, type LogEntry } from "./history-git.js";
import { createVersionReader, readLockfileLog } from "./history-lockfiles.js";
import { addManifestChanges } from "./history-manifest.js";
import { locateWindows } from "./history-refs.js";
import type { HistoryOptions, HistoryReport } from "./history-types.js";
import { trackPackage, unique } from "./history-versions.js";

export type {
  CommitRef,
  HistoryOptions,
  HistoryReport,
  ManifestChange,
  PackageHistory,
  RefSet,
  VersionWindow,
} from "./history-types.js";

/**
 * When did the affected versions of each package enter and leave the repository's lockfiles, and
 * which branches and tags could therefore have installed them? Reads lockfile text out of git
 * (nothing is checked out, nothing is installed) and parses it with the lockfile parsers, so it
 * works for npm, pnpm, yarn and bun lockfiles alike.
 */
export async function scanHistory(options: HistoryOptions): Promise<HistoryReport> {
  const { cwd, targets } = options;
  const max = options.maxCommits ?? 500;
  const maxRefs = options.maxRefs ?? 200;
  const base = emptyReport(targets);

  const unavailable = await checkRepository(cwd);
  if (unavailable !== undefined) {
    return { ...base, reason: unavailable };
  }

  const shallow = (await git(cwd, ["rev-parse", "--is-shallow-repository"])).trim() === "true";
  const notes: string[] = [];
  if (shallow) {
    notes.push("This is a shallow clone: history older than the clone depth is not available.");
  }

  const { lockEntries, commits, truncated } = await readLockfileLog(cwd, max, notes);
  const lockfiles = unique(lockEntries.map((entry) => entry.path)).toSorted();
  if (lockEntries.length === 0) {
    return { ...base, shallow, notes, reason: "no commit in the repository changed a lockfile" };
  }

  const blobs = await readBlobs(cwd, lockfileBlobIds(lockEntries));
  const versionsIn = createVersionReader(blobs, targets);
  const unreadable = new Set<string>();
  const packages = targets.map((target) =>
    trackPackage({ target, lockEntries, versionsIn, unreadable }),
  );

  // Which lockfiles, at HEAD and at the tip of each branch and tag, have an affected version.
  await locateWindows(packages, { cwd, targets, lockfiles, blobs, versionsIn, maxRefs, notes });
  // package.json: when the declared range of each package changed.
  await addManifestChanges(cwd, max, packages);

  return {
    available: true,
    scannedCommits: commits,
    truncated,
    shallow,
    lockfiles,
    unreadable: unreadable.size,
    packages,
    notes,
  };
}

function emptyReport(targets: HistoryOptions["targets"]): HistoryReport {
  return {
    available: false,
    scannedCommits: 0,
    truncated: false,
    shallow: false,
    lockfiles: [],
    unreadable: 0,
    packages: targets.map((target) => ({
      packageName: target.name,
      versionsSeen: [],
      windows: [],
      manifestChanges: [],
    })),
    notes: [],
  };
}

/** Why there is no history to read, or `undefined` when there is a repository with commits. */
async function checkRepository(cwd: string): Promise<string | undefined> {
  try {
    await git(cwd, ["rev-parse", "--git-dir"]);
  } catch {
    return "not a git checkout, so there is no history to read";
  }
  const hasCommits = await git(cwd, ["rev-parse", "--verify", "--quiet", "HEAD"]).then(
    () => true,
    () => false,
  );
  return hasCommits ? undefined : "the repository has no commits yet";
}

function lockfileBlobIds(lockEntries: LogEntry[]): string[] {
  return unique(
    lockEntries
      .flatMap((entry) => [entry.oldOid, entry.newOid])
      .filter((oid): oid is string => oid !== undefined),
  );
}
