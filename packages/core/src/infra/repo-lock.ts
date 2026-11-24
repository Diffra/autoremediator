/**
 * The repository lock: one remediation at a time per project directory. The lock is a directory,
 * because `mkdir` either creates it or fails atomically. It records who holds it, so a lock left
 * behind by a process that died is taken over instead of blocking every later run.
 */
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";

import { sleep } from "../shared/time.js";

interface RepoLockOptions {
  timeoutMs?: number;
  retryDelayMs?: number;
}

interface RepoLock {
  lockPath: string;
  release: () => Promise<void>;
}

interface LockOwner {
  pid: number;
  hostname: string;
  startedAt: string;
}

/** A lock directory with no readable owner record is left over once it is this old. */
const ORPHAN_AFTER_MS = 60_000;

export async function acquireRepoLock(
  cwd: string,
  options: RepoLockOptions = {},
): Promise<RepoLock> {
  const timeoutMs = options.timeoutMs ?? 15_000;
  const retryDelayMs = options.retryDelayMs ?? 125;
  const lockRoot = join(cwd, ".autoremediator", "locks");
  const lockPath = join(lockRoot, "remediation.lock");
  const startedAt = Date.now();

  await mkdir(lockRoot, { recursive: true });

  while (true) {
    if (await tryCreateLock(lockPath)) {
      return {
        lockPath,
        release: async () => {
          await rm(lockPath, { recursive: true, force: true });
        },
      };
    }
    if (await isAbandoned(lockPath)) {
      await rm(lockPath, { recursive: true, force: true });
      continue;
    }
    if (Date.now() - startedAt > timeoutMs) {
      throw new Error(`Timed out waiting for repository lock at ${lockPath}.`);
    }
    await sleep(retryDelayMs);
  }
}

export async function withRepoLock<T>(
  cwd: string,
  fn: () => Promise<T>,
  options?: RepoLockOptions,
): Promise<T> {
  const lock = await acquireRepoLock(cwd, options);
  try {
    return await fn();
  } finally {
    await lock.release();
  }
}

/** Creates the lock and records its owner. Returns false when someone else holds it. */
async function tryCreateLock(lockPath: string): Promise<boolean> {
  try {
    await mkdir(lockPath, { recursive: false });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      return false;
    }
    // Anything else (no permission, no space) will not clear by waiting.
    throw error;
  }
  const owner: LockOwner = {
    pid: process.pid,
    hostname: hostname(),
    startedAt: new Date().toISOString(),
  };
  try {
    await writeFile(join(lockPath, "owner.json"), JSON.stringify(owner), "utf8");
  } catch (error) {
    await rm(lockPath, { recursive: true, force: true });
    throw error;
  }
  return true;
}

/** True when the lock's owner is a process on this machine that no longer exists. */
async function isAbandoned(lockPath: string): Promise<boolean> {
  const owner = await readOwner(lockPath);
  if (owner) {
    return owner.hostname === hostname() && !processIsAlive(owner.pid);
  }
  // No owner record: just created and not yet written, or left by a crash between the two steps.
  try {
    return Date.now() - (await stat(lockPath)).mtimeMs > ORPHAN_AFTER_MS;
  } catch {
    // The directory is gone: the holder released it, so try to take it.
    return false;
  }
}

async function readOwner(lockPath: string): Promise<LockOwner | undefined> {
  try {
    const value: unknown = JSON.parse(await readFile(join(lockPath, "owner.json"), "utf8"));
    if (typeof value !== "object" || value === null) return undefined;
    const { pid, hostname: host, startedAt } = value as Record<string, unknown>;
    if (typeof pid !== "number" || typeof host !== "string" || typeof startedAt !== "string") {
      return undefined;
    }
    return { pid, hostname: host, startedAt };
  } catch {
    // Missing or half-written record: treated as "no owner record".
    return undefined;
  }
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means the process exists but belongs to someone else.
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}
