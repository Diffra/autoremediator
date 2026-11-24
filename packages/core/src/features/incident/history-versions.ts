/** Which versions of a package each lockfile blob holds, and when each version came and went. */

import semver from "semver";

import type { LogEntry } from "./history-git.js";
import type { VersionReader } from "./history-lockfiles.js";
import type { CommitRef, PackageHistory, RefSet } from "./history-types.js";

interface Track {
  entered: CommitRef[];
  left: CommitRef[];
  previous: string[];
}

interface Seen {
  first: CommitRef;
  last: CommitRef;
}

interface Tracking {
  tracks: Map<string, Track>;
  seen: Map<string, Seen>;
}

export const isAffected = (version: string, range: string): boolean =>
  semver.valid(version) !== null && semver.satisfies(version, range, { includePrerelease: true });

export const byVersionDesc = (a: string, b: string): number =>
  semver.valid(a) && semver.valid(b) ? semver.rcompare(a, b) : b.localeCompare(a);

export const emptyRefs = (): RefSet => ({ branches: [], tags: [] });

export const unique = <T>(values: T[]): T[] => [...new Set(values)];

export function refSet(names: string[]): RefSet {
  const refs = emptyRefs();
  for (const name of names) {
    if (name.startsWith("refs/tags/")) {
      refs.tags.push(name.slice("refs/tags/".length));
    } else if (name.startsWith("refs/heads/")) {
      refs.branches.push(name.slice("refs/heads/".length));
    } else if (name.startsWith("refs/remotes/") && !name.endsWith("/HEAD")) {
      refs.branches.push(name.slice("refs/remotes/".length));
    }
  }
  return { branches: refs.branches.toSorted(), tags: refs.tags.toSorted() };
}

/**
 * The history of one package: every version seen, and a window for each affected version in each
 * lockfile. `unreadable` collects the commit and path of every lockfile that could not be read.
 */
export function trackPackage(input: {
  target: { name: string; range: string };
  lockEntries: LogEntry[];
  versionsIn: VersionReader;
  unreadable: Set<string>;
}): PackageHistory {
  const { target, lockEntries, versionsIn, unreadable } = input;
  const tracking: Tracking = { tracks: new Map(), seen: new Map() };

  // `lockEntries` is newest first; walking it backwards visits history oldest first.
  for (const entry of lockEntries.toReversed()) {
    const before = versionsIn(entry.oldOid, entry.path, target.name);
    const after = versionsIn(entry.newOid, entry.path, target.name);
    if (before === undefined || after === undefined) {
      unreadable.add(`${entry.commit.sha}:${entry.path}`);
      continue;
    }
    recordEntered({ tracking, entry, before, after, range: target.range });
    for (const version of before) {
      if (!after.includes(version)) {
        trackOf(tracking.tracks, entry.path, version).left.unshift(entry.commit);
      }
    }
  }

  return {
    packageName: target.name,
    versionsSeen: toVersionsSeen(tracking.seen, target.range),
    windows: toWindows(tracking.tracks, target.range),
    manifestChanges: [],
  };
}

function trackOf(tracks: Map<string, Track>, path: string, version: string): Track {
  const key = `${path}\0${version}`;
  let track = tracks.get(key);
  if (!track) {
    track = { entered: [], left: [], previous: [] };
    tracks.set(key, track);
  }
  return track;
}

function recordEntered(input: {
  tracking: Tracking;
  entry: LogEntry;
  before: string[];
  after: string[];
  range: string;
}): void {
  const { tracking, entry, before, after, range } = input;
  for (const version of after) {
    const earlier = tracking.seen.get(version);
    tracking.seen.set(version, { first: earlier?.first ?? entry.commit, last: entry.commit });
    if (before.includes(version)) {
      continue;
    }
    const track = trackOf(tracking.tracks, entry.path, version);
    track.entered.unshift(entry.commit);
    // What the lockfile had right before this version first arrived.
    if (track.entered.length === 1) {
      track.previous = before.filter((other) => !isAffected(other, range)).toSorted(byVersionDesc);
    }
  }
}

function toVersionsSeen(seen: Map<string, Seen>, range: string): PackageHistory["versionsSeen"] {
  return [...seen.entries()]
    .map(([version, window]) => ({
      version,
      affected: isAffected(version, range),
      firstSeen: window.first,
      lastSeen: window.last,
    }))
    .toSorted((a, b) => byVersionDesc(a.version, b.version));
}

function toWindows(tracks: Map<string, Track>, range: string): PackageHistory["windows"] {
  const affectedKeys = [...tracks.entries()].filter(([key]) =>
    isAffected(key.split("\0")[1]!, range),
  );
  return affectedKeys.map(([key, track]) => {
    const [lockfile = "", version = ""] = key.split("\0");
    return {
      version,
      lockfile,
      entered: track.entered,
      left: track.left,
      previousVersions: track.previous,
      presentAtHead: false,
      atTip: emptyRefs(),
      passedThrough: emptyRefs(),
    };
  });
}
