/** Which branches and tags install an affected version: at their tip, or through their history. */

import { git, readBlobs } from "./history-git.js";
import type { VersionReader } from "./history-lockfiles.js";
import type { PackageHistory, VersionWindow } from "./history-types.js";
import { byVersionDesc, refSet, unique } from "./history-versions.js";

interface Probe {
  ref: string;
  path: string;
}

interface RefContext {
  cwd: string;
  targets: Array<{ name: string; range: string }>;
  lockfiles: string[];
  blobs: Map<string, string | undefined>;
  versionsIn: VersionReader;
  maxRefs: number;
  notes: string[];
}

/**
 * Fills in `presentAtHead`, `atTip` and `passedThrough` on every window, and orders the windows.
 * Pushes a note when there are more branches or tags than `maxRefs`.
 */
export async function locateWindows(
  packages: PackageHistory[],
  context: RefContext,
): Promise<void> {
  const { cwd, targets, lockfiles, blobs, versionsIn, maxRefs, notes } = context;
  const refs = await listRefs(cwd, maxRefs, notes);
  const probes = refs.flatMap((ref) => lockfiles.map((path) => ({ ref, path })));
  const tipOids = await readTipOids(cwd, probes, blobs);

  for (const history of packages) {
    const target = targets.find((candidate) => candidate.name === history.packageName)!;
    for (const window of history.windows) {
      const atTip = markTips({ window, probes, tipOids, versionsIn, name: target.name });
      window.atTip = refSet(atTip);
      window.passedThrough = await readPassedThrough(cwd, window, atTip);
    }
    history.windows.sort(
      (a, b) => byVersionDesc(a.version, b.version) || a.lockfile.localeCompare(b.lockfile),
    );
  }
}

/** HEAD, then the branches, then the tags, each capped at `maxRefs`. */
async function listRefs(cwd: string, maxRefs: number, notes: string[]): Promise<string[]> {
  const refNames = (
    await git(cwd, [
      "for-each-ref",
      "--format=%(refname)",
      "refs/heads",
      "refs/remotes",
      "refs/tags",
    ]).catch(() => "")
  )
    .split("\n")
    .filter((name) => name !== "" && !name.endsWith("/HEAD"));
  const branchNames = refNames.filter((name) => !name.startsWith("refs/tags/"));
  const tagNames = refNames.filter((name) => name.startsWith("refs/tags/"));
  if (branchNames.length > maxRefs || tagNames.length > maxRefs) {
    notes.push(
      `More than ${maxRefs} branches or tags exist; only the first ${maxRefs} of each were checked for what they install.`,
    );
  }
  return ["HEAD", ...branchNames.slice(0, maxRefs), ...tagNames.slice(0, maxRefs)];
}

/** The blob each probe resolves to (one line per probe), with the new blobs read into `blobs`. */
async function readTipOids(
  cwd: string,
  probes: Probe[],
  blobs: Map<string, string | undefined>,
): Promise<string[]> {
  const probeOut = await git(
    cwd,
    ["cat-file", "--batch-check=%(objectname) %(objecttype)"],
    `${probes.map((probe) => `${probe.ref}:${probe.path}`).join("\n")}\n`,
  ).catch(() => "");
  const tipOids = probeOut.split("\n");
  const tipBlobs = unique(
    tipOids
      .map((line) => line.split(" "))
      .flatMap(([id, type]) => (type === "blob" && id ? [id] : [])),
  );
  for (const [blob, text] of await readBlobs(
    cwd,
    tipBlobs.filter((candidate) => !blobs.has(candidate)),
  )) {
    blobs.set(blob, text);
  }
  return tipOids;
}

/** Sets `presentAtHead` and returns the refs (other than HEAD) whose tip has the window's version. */
function markTips(input: {
  window: VersionWindow;
  probes: Probe[];
  tipOids: string[];
  versionsIn: VersionReader;
  name: string;
}): string[] {
  const { window, probes, tipOids, versionsIn, name } = input;
  const atTip: string[] = [];
  for (const [index, probe] of probes.entries()) {
    if (probe.path !== window.lockfile) {
      continue;
    }
    const [oid, type] = (tipOids[index] ?? "").split(" ");
    if (type !== "blob" || !oid) {
      continue;
    }
    if (!versionsIn(oid, probe.path, name)?.includes(window.version)) {
      continue;
    }
    if (probe.ref === "HEAD") {
      window.presentAtHead = true;
    } else {
      atTip.push(probe.ref);
    }
  }
  return atTip;
}

/** Refs whose history contains an entering commit but whose tip no longer has the version. */
async function readPassedThrough(
  cwd: string,
  window: VersionWindow,
  atTip: string[],
): Promise<VersionWindow["passedThrough"]> {
  const entering = window.entered.slice(0, 20);
  const through = (
    await Promise.all(
      entering.map((commit) =>
        git(cwd, [
          "for-each-ref",
          "--format=%(refname)",
          `--contains=${commit.sha}`,
          "refs/heads",
          "refs/remotes",
          "refs/tags",
        ]).catch(() => ""),
      ),
    )
  )
    .flatMap((text) => text.split("\n"))
    .filter((name) => name !== "");
  const tipSet = new Set(atTip);
  return refSet(unique(through).filter((name) => !tipSet.has(name)));
}
