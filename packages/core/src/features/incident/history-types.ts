/** The shapes of the history report: what `scanHistory` takes and returns. */

export interface CommitRef {
  sha: string;
  /** Commit date, ISO 8601. */
  date: string;
}

export interface RefSet {
  branches: string[];
  tags: string[];
}

/** One version of the package in one lockfile, and when it came and went. */
export interface VersionWindow {
  version: string;
  /** The lockfile, relative to the repository root. */
  lockfile: string;
  /** Commits whose lockfile has the version where the commit before it did not. Newest first. */
  entered: CommitRef[];
  /** Commits whose lockfile lost it. Newest first. */
  left: CommitRef[];
  /** Versions of the package the lockfile had just before the version first entered, newest first. */
  previousVersions: string[];
  /** The lockfile at HEAD still has it. */
  presentAtHead: boolean;
  /** Branches and tags whose tip has it in the lockfile: a build of one of those installs it. */
  atTip: RefSet;
  /** Branches and tags whose history passes through an entering commit but whose tip no longer has it. */
  passedThrough: RefSet;
}

export interface ManifestChange {
  commit: CommitRef;
  /** What package.json declared before (absent: the package was not listed). */
  from?: string;
  /** What it declares after (absent: removed). */
  to?: string;
}

export interface PackageHistory {
  packageName: string;
  /** Every version of the package the lockfiles ever had in the scanned commits, with when. */
  versionsSeen: Array<{
    version: string;
    affected: boolean;
    firstSeen: CommitRef;
    lastSeen: CommitRef;
  }>;
  windows: VersionWindow[];
  manifestChanges: ManifestChange[];
}

export interface HistoryReport {
  /** False when there is no history to read (not a git checkout, or no commit touched a lockfile). */
  available: boolean;
  reason?: string;
  /** Lockfile commits examined. */
  scannedCommits: number;
  /** More lockfile commits exist than `maxCommits`; older ones were not examined. */
  truncated: boolean;
  shallow: boolean;
  lockfiles: string[];
  /** Lockfile versions that could not be read (corrupt, or a format that is not supported). */
  unreadable: number;
  packages: PackageHistory[];
  notes: string[];
}

export interface HistoryOptions {
  cwd: string;
  /** The packages and the version range of each that counts as affected. */
  targets: Array<{ name: string; range: string }>;
  /** Most lockfile commits to examine, newest first (default 500). */
  maxCommits?: number;
  /** Most branches and most tags to evaluate (default 200 each). */
  maxRefs?: number;
}
