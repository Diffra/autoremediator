/** When the range a package.json declares for each package changed. */

import { isRecord } from "../../shared/guards.js";
import { readBlobs, readLog, type LogEntry } from "./history-git.js";
import type { ManifestChange, PackageHistory } from "./history-types.js";
import { unique } from "./history-versions.js";

const DEPENDENCY_FIELDS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];
const MAX_CHANGES = 50;

/** Sets `manifestChanges` on each package: newest first, at most 50. */
export async function addManifestChanges(
  cwd: string,
  max: number,
  packages: PackageHistory[],
): Promise<void> {
  const manifest = await readLog(cwd, ["package.json"], max).catch(() => ({
    entries: [] as LogEntry[],
    commits: 0,
  }));
  const manifestBlobs = await readBlobs(
    cwd,
    unique(
      manifest.entries
        .flatMap((entry) => [entry.oldOid, entry.newOid])
        .filter((oid): oid is string => oid !== undefined),
    ),
  );
  for (const history of packages) {
    const changes: ManifestChange[] = [];
    for (const entry of manifest.entries) {
      const from = declared(manifestBlobs, entry.oldOid, history.packageName);
      const to = declared(manifestBlobs, entry.newOid, history.packageName);
      if (from === to) {
        continue;
      }
      const change: ManifestChange = { commit: entry.commit };
      if (from !== undefined) {
        change.from = from;
      }
      if (to !== undefined) {
        change.to = to;
      }
      changes.push(change);
    }
    history.manifestChanges = changes.slice(0, MAX_CHANGES);
  }
}

function declared(
  blobs: Map<string, string | undefined>,
  oid: string | undefined,
  name: string,
): string | undefined {
  const text = oid === undefined ? undefined : blobs.get(oid);
  if (text === undefined) {
    return undefined;
  }
  try {
    const json: unknown = JSON.parse(text);
    if (!isRecord(json)) {
      return undefined;
    }
    for (const field of DEPENDENCY_FIELDS) {
      const table = json[field];
      const value = isRecord(table) ? table[name] : undefined;
      if (typeof value === "string") {
        return value;
      }
    }
  } catch {
    // A package.json that does not parse says nothing about the package.
  }
  return undefined;
}
