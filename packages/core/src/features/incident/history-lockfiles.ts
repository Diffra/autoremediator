/** Reading lockfiles: which commits changed one, and which versions of a package a blob holds. */

import {
  LOCKFILE_NAMES,
  lockFormatOf,
  parseLockGraph,
  versionsOfPackage,
} from "../scan/lock-graph/index.js";
import { readLog, type LogEntry } from "./history-git.js";

/** Versions of `name` in the lockfile blob `oid` at `path`; `undefined` when it cannot be read. */
export type VersionReader = (
  oid: string | undefined,
  path: string,
  name: string,
) => string[] | undefined;

/** The newest `max` commits that changed a lockfile, with a note when that cut history short. */
export async function readLockfileLog(
  cwd: string,
  max: number,
  notes: string[],
): Promise<{ lockEntries: LogEntry[]; commits: number; truncated: boolean }> {
  const lockPathspecs = [
    ...LOCKFILE_NAMES.map((name) => `:(glob)**/${name}`),
    ":(exclude,glob)**/node_modules/**",
  ];
  const { entries, commits } = await readLog(cwd, lockPathspecs, max);
  const truncated = commits >= max;
  if (truncated) {
    notes.push(
      `Only the newest ${max} commits that changed a lockfile were examined; older ones were not.`,
    );
  }
  if (entries.some((entry) => entry.path.endsWith("bun.lockb"))) {
    notes.push(
      "bun.lockb (the binary bun lockfile) cannot be read; only the text bun.lock is analysed.",
    );
  }
  const lockEntries = entries.filter((entry) => lockFormatOf(entry.path) !== undefined);
  return { lockEntries, commits, truncated };
}

/** Versions of each package in each distinct lockfile blob; parsed once however often it recurs. */
export function createVersionReader(
  blobs: Map<string, string | undefined>,
  targets: Array<{ name: string }>,
): VersionReader {
  const cache = new Map<string, Map<string, string[]> | "unreadable">();
  return (oid, path, name) => {
    if (oid === undefined) {
      return [];
    }
    let perPackage = cache.get(`${oid}:${path}`);
    if (perPackage === undefined) {
      perPackage = parseBlobVersions(blobs.get(oid), path, targets);
      cache.set(`${oid}:${path}`, perPackage);
    }
    return perPackage === "unreadable" ? undefined : (perPackage.get(name) ?? []);
  };
}

function parseBlobVersions(
  text: string | undefined,
  path: string,
  targets: Array<{ name: string }>,
): Map<string, string[]> | "unreadable" {
  if (text === undefined) {
    return "unreadable";
  }
  try {
    const graph = parseLockGraph(path, text);
    return new Map(
      targets.map((target) => [target.name, graph ? versionsOfPackage(graph, target.name) : []]),
    );
  } catch {
    return "unreadable";
  }
}
