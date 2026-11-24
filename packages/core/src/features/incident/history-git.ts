/** Reading commits and blobs out of git for the history scan: nothing is checked out. */

import { safeExeca } from "../../shared/exec/safe-exec.js";
import type { CommitRef } from "./history-types.js";

const ZERO = /^0+$/;
const MAX_BLOB_BYTES = 40 * 1024 * 1024;
const BATCH = 25;

/** One path changed by one commit, with the blob before and after. */
export interface LogEntry {
  commit: CommitRef;
  path: string;
  oldOid: string | undefined;
  newOid: string | undefined;
}

export async function git(cwd: string, args: string[], input?: string): Promise<string> {
  const result = await safeExeca(
    "git",
    ["-c", "core.quotepath=off", "--no-optional-locks", ...args],
    {
      cwd,
      stdio: "pipe",
      reject: false,
      maxBuffer: 256 * 1024 * 1024,
      ...(input === undefined ? {} : { input }),
    },
  );
  if (result.exitCode !== 0) {
    throw new Error(`git ${args[0]} failed: ${result.stderr.split("\n")[0]}`);
  }
  return result.stdout;
}

/** Contents of blobs by id; `undefined` for a missing or oversized one. */
export async function readBlobs(
  cwd: string,
  oids: string[],
): Promise<Map<string, string | undefined>> {
  const contents = new Map<string, string | undefined>();
  for (let start = 0; start < oids.length; start += BATCH) {
    const chunk = oids.slice(start, start + BATCH);
    const result = await safeExeca("git", ["--no-optional-locks", "cat-file", "--batch"], {
      cwd,
      encoding: "buffer",
      stdio: "pipe",
      reject: false,
      maxBuffer: 1024 * 1024 * 1024,
      input: `${chunk.join("\n")}\n`,
    });
    collectBatchOutput(Buffer.from(result.stdout), chunk, contents);
  }
  return contents;
}

/** Commits that changed any of `pathspecs`, newest first, with the blob before and after for each path. */
export async function readLog(
  cwd: string,
  pathspecs: string[],
  max: number,
): Promise<{ entries: LogEntry[]; commits: number }> {
  const out = await git(cwd, [
    "log",
    "--all",
    "--no-renames",
    "--raw",
    "--no-abbrev",
    `--max-count=${max}`,
    "--format=@@%H%x09%cI",
    "--",
    ...pathspecs,
  ]);
  const entries: LogEntry[] = [];
  let commit: CommitRef | undefined;
  let commits = 0;
  for (const line of out.split("\n")) {
    if (line.startsWith("@@")) {
      commit = parseCommitLine(line);
      commits += 1;
    } else if (line.startsWith(":") && commit) {
      const entry = parseRawLine(line, commit);
      if (entry) {
        entries.push(entry);
      }
    }
  }
  return { entries, commits };
}

/** Walks the `cat-file --batch` stream: a header line, then the blob, then a newline. */
function collectBatchOutput(
  out: Buffer,
  chunk: string[],
  contents: Map<string, string | undefined>,
): void {
  let at = 0;
  for (const oid of chunk) {
    const newline = out.indexOf(0x0a, at);
    if (newline === -1) {
      break;
    }
    const header = out.subarray(at, newline).toString("utf8").split(" ");
    at = newline + 1;
    if (header[1] !== "blob") {
      contents.set(oid, undefined);
      continue;
    }
    const size = Number(header[2]);
    contents.set(
      oid,
      size > MAX_BLOB_BYTES ? undefined : out.subarray(at, at + size).toString("utf8"),
    );
    at += size + 1;
  }
}

function parseCommitLine(line: string): CommitRef {
  const [sha = "", date = ""] = line.slice(2).split("\t");
  // Normalised to UTC, so the same commit reads the same wherever it was made.
  return { sha, date: Number.isNaN(Date.parse(date)) ? date : new Date(date).toISOString() };
}

function parseRawLine(line: string, commit: CommitRef): LogEntry | undefined {
  const tab = line.indexOf("\t");
  if (tab === -1) {
    return undefined;
  }
  const [, , oldOid = "", newOid = ""] = line.slice(1, tab).split(" ");
  const path = line.slice(tab + 1);
  // A path git had to quote (tabs, newlines, quotes) is skipped rather than guessed at.
  if (path.startsWith('"')) {
    return undefined;
  }
  return {
    commit,
    path,
    oldOid: ZERO.test(oldOid) ? undefined : oldOid,
    newOid: ZERO.test(newOid) ? undefined : newOid,
  };
}
