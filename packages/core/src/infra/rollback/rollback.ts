import { execFileSync, execSync } from "node:child_process";
import {
  existsSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";

import { RollbackError, errorMessage } from "../../shared/errors.js";
import { safeExeca } from "../../shared/exec/safe-exec.js";
import { MEMORY_PATH, TRACK_RECORD_PATH } from "../../shared/state-paths.js";

export interface ProjectSnapshot {
  cwd: string;
  isGit: boolean;
  /** Absolute git work-tree root; porcelain status paths are relative to this, not to cwd. */
  gitRoot?: string;
  gitStatusBefore?: string[];
  fileSnapshots: Map<string, string | null>; // relative path -> content or null (if non-existent)
}

const MANIFEST_PATTERNS = [
  /package\.json$/,
  /^(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|deno\.lock)$/,
  /deno\.jsonc?$/,
  /\.patch$/,
  /\.autoremediator\.ya?ml$/,
  /^pnpm-workspace\.ya?ml$/,
  /tsconfig.*\.json$/,
];

const IGNORED_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", ".pnpm-store"]);

// Global registry of active rollback snapshots for dynamic file touch tracking
const activeSnapshots: Set<ProjectSnapshot> = new Set();

export function registerActiveSnapshot(snapshot: ProjectSnapshot): void {
  activeSnapshots.add(snapshot);
}

export function unregisterActiveSnapshot(snapshot: ProjectSnapshot): void {
  activeSnapshots.delete(snapshot);
}

/**
 * Registers an arbitrary file that is about to be modified/created in any active rollback transactions.
 */
export function recordFileTouch(filePath: string): void {
  for (const snapshot of activeSnapshots) {
    const absPath = isAbsolute(filePath) ? filePath : join(snapshot.cwd, filePath);
    const relPath = relative(snapshot.cwd, absPath);
    if (relPath.startsWith("..") || isAbsolute(relPath)) continue;

    if (!snapshot.fileSnapshots.has(relPath)) {
      if (existsSync(absPath)) {
        try {
          snapshot.fileSnapshots.set(relPath, readFileSync(absPath, "latin1"));
        } catch {
          try {
            snapshot.fileSnapshots.set(relPath, readFileSync(absPath).toString("base64"));
          } catch {
            snapshot.fileSnapshots.set(relPath, null);
          }
        }
      } else {
        snapshot.fileSnapshots.set(relPath, null);
      }
    }
  }
}

/**
 * Dynamically discovers manifest, lockfile, and patch configuration files across the project tree.
 */
export function discoverProjectFiles(dir: string, maxDepth = 4, currentDepth = 0): string[] {
  const discovered: string[] = [];
  if (currentDepth > maxDepth) return discovered;

  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return discovered;
  }

  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry)) continue;
    const fullPath = join(dir, entry);
    let stat;
    try {
      stat = statSync(fullPath);
    } catch {
      continue;
    }

    if (stat.isDirectory()) {
      discovered.push(...discoverProjectFiles(fullPath, maxDepth, currentDepth + 1));
    } else if (stat.isFile()) {
      const matchesPattern = MANIFEST_PATTERNS.some((pattern) => pattern.test(entry));
      if (matchesPattern) {
        discovered.push(fullPath);
      }
    }
  }

  return discovered;
}

async function isGitRepository(cwd: string): Promise<boolean> {
  try {
    const res = await safeExeca("git", ["rev-parse", "--is-inside-work-tree"], {
      cwd,
      stdio: "pipe",
    });
    return res.stdout.trim() === "true";
  } catch {
    return false;
  }
}

async function resolveGitRoot(cwd: string): Promise<string | undefined> {
  try {
    const res = await safeExeca("git", ["rev-parse", "--show-toplevel"], { cwd, stdio: "pipe" });
    const root = res.stdout.trim();
    return root.length > 0 ? root : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Map a `git status --porcelain` path (relative to the repo root) to an absolute path,
 * returning null unless it lies strictly inside the snapshot's cwd. Rollback must never
 * delete or revert anything outside the project directory it was asked to protect.
 */
function resolveGitStatusPath(snapshot: ProjectSnapshot, filePath: string): string | null {
  const full = resolve(snapshot.gitRoot ?? snapshot.cwd, filePath);
  let realCwd = snapshot.cwd;
  try {
    realCwd = realpathSync(snapshot.cwd);
  } catch {
    // fall back to the spelling we were given
  }
  const rel = relative(realCwd, full);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return null;
  // The autonomy track record is history, not project state: a rollback must not rewind it.
  // Remediation memory is history too.
  const normalized = rel.replaceAll("\\", "/");
  if (normalized === TRACK_RECORD_PATH || normalized === MEMORY_PATH) return null;
  // Everything else the tool keeps under `.autoremediator/` (other runs, recipes, evidence, locks) is
  // its own bookkeeping or committed knowledge, not project state, whether or not it is gitignored.
  if (normalized.startsWith(".autoremediator/")) return null;
  return join(snapshot.cwd, rel);
}

export function parsePorcelainLines(stdout: string): string[] {
  return stdout
    .split(/\r?\n/)
    .map((l) => l.replace(/\r$/, ""))
    .filter((l) => l.length >= 3 && l.slice(0, 2).trim().length > 0);
}

export function parseGitPorcelainLine(
  line: string,
): { statusCode: string; filePath: string } | null {
  if (!line || line.length < 3) return null;
  const statusCode = line.slice(0, 2).trim();
  let filePath = line.slice(3).trim();
  if (filePath.includes(" -> ")) {
    filePath = filePath.split(" -> ").pop()!.trim();
  }
  if (filePath.startsWith('"') && filePath.endsWith('"')) {
    filePath = filePath.slice(1, -1).replaceAll(String.raw`\"`, '"');
  }
  return { statusCode, filePath };
}

async function getGitStatusPorcelain(cwd: string): Promise<string[]> {
  try {
    const res = await safeExeca("git", ["status", "--porcelain=v1", "-uall"], {
      cwd,
      stdio: "pipe",
    });
    return parsePorcelainLines(res.stdout);
  } catch {
    return [];
  }
}

/**
 * Creates an intelligent, Git-aware snapshot of the repository state.
 */
export async function createProjectSnapshot(
  cwd: string,
  explicitFiles?: string[],
): Promise<ProjectSnapshot> {
  const isGit = await isGitRepository(cwd);
  const gitStatusBefore = isGit ? await getGitStatusPorcelain(cwd) : undefined;
  const gitRoot = isGit ? await resolveGitRoot(cwd) : undefined;
  const fileSnapshots = new Map<string, string | null>();

  const targetFiles = explicitFiles
    ? explicitFiles.map((f) => (isAbsolute(f) ? f : join(cwd, f)))
    : discoverProjectFiles(cwd);

  for (const fullPath of targetFiles) {
    const relPath = relative(cwd, fullPath);
    if (existsSync(fullPath)) {
      try {
        fileSnapshots.set(relPath, readFileSync(fullPath, "latin1"));
      } catch {
        try {
          fileSnapshots.set(relPath, readFileSync(fullPath).toString("base64"));
        } catch {
          // Skip unreadable files
        }
      }
    } else {
      fileSnapshots.set(relPath, null);
    }
  }

  const snapshot: ProjectSnapshot = {
    cwd,
    isGit,
    gitRoot,
    gitStatusBefore,
    fileSnapshots,
  };

  return snapshot;
}

/**
 * Restores project state from snapshot using Git transaction restore or in-memory fallback.
 * Every step is attempted; a file that could not be put back is reported by a `RollbackError`
 * rather than a rollback that looks clean.
 */
export async function restoreProjectSnapshot(snapshot: ProjectSnapshot): Promise<void> {
  const failures = restoreTrackedFiles(snapshot);

  if (snapshot.isGit) {
    // Git state that cannot be read leaves only the tracked files above to restore.
    const currentStatus = await getGitStatusPorcelain(snapshot.cwd);
    for (const action of gitCleanupActions(snapshot, currentStatus)) {
      if (action.kind === "remove") {
        removeQuietly(action.path, failures, snapshot.cwd);
        continue;
      }
      try {
        await safeExeca("git", ["checkout", "--", action.path], {
          cwd: snapshot.cwd,
          stdio: "pipe",
        });
      } catch {
        failures.push(relative(snapshot.cwd, action.path));
      }
    }
  }
  assertRestored(failures);
}

/**
 * Synchronously restores project state from snapshot.
 */
export function restoreProjectSnapshotSync(snapshot: ProjectSnapshot): void {
  const failures = restoreTrackedFiles(snapshot);

  if (snapshot.isGit) {
    let currentStatus: string[] = [];
    try {
      const stdout = execSync("git status --porcelain=v1 -uall", {
        cwd: snapshot.cwd,
        stdio: ["pipe", "pipe", "ignore"],
        encoding: "utf8",
      });
      currentStatus = parsePorcelainLines(stdout);
    } catch {
      // Git state that cannot be read leaves only the tracked files above to restore.
    }
    for (const action of gitCleanupActions(snapshot, currentStatus)) {
      if (action.kind === "remove") {
        removeQuietly(action.path, failures, snapshot.cwd);
        continue;
      }
      try {
        execFileSync("git", ["checkout", "--", action.path], {
          cwd: snapshot.cwd,
          stdio: "ignore",
        });
      } catch {
        failures.push(relative(snapshot.cwd, action.path));
      }
    }
  }
  assertRestored(failures);
}

/** Puts back every snapshotted file and removes manifest files created since. Returns what failed. */
function restoreTrackedFiles(snapshot: ProjectSnapshot): string[] {
  const failures: string[] = [];
  for (const [relPath, previousContent] of snapshot.fileSnapshots.entries()) {
    const fullPath = join(snapshot.cwd, relPath);
    // A snapshot can come from a file the project carries; never write or delete outside it.
    const escape = relative(snapshot.cwd, fullPath);
    if (escape.startsWith("..") || isAbsolute(escape)) {
      throw new Error(`Refusing to restore "${relPath}": it is outside the project.`);
    }
    try {
      if (previousContent === null) {
        rmSync(fullPath, { force: true, recursive: true });
      } else {
        writeFileSync(fullPath, previousContent, "latin1");
      }
    } catch {
      failures.push(relPath);
    }
  }

  // Manifest and patch files that appeared since the snapshot were not in it.
  for (const fullPath of discoverProjectFiles(snapshot.cwd)) {
    const relPath = relative(snapshot.cwd, fullPath);
    if (!snapshot.fileSnapshots.has(relPath)) {
      removeQuietly(fullPath, failures, snapshot.cwd);
    }
  }
  return failures;
}

function removeQuietly(path: string, failures: string[], cwd: string): void {
  try {
    rmSync(path, { force: true, recursive: true });
  } catch {
    failures.push(relative(cwd, path));
  }
}

interface GitCleanupAction {
  kind: "remove" | "checkout";
  path: string;
}

/** What to undo for files git reports changed since the snapshot: delete new ones, revert tracked ones. */
function gitCleanupActions(snapshot: ProjectSnapshot, currentStatus: string[]): GitCleanupAction[] {
  const beforeSet = new Set(snapshot.gitStatusBefore ?? []);
  const actions: GitCleanupAction[] = [];
  for (const line of currentStatus) {
    if (beforeSet.has(line)) continue;
    const parsed = parseGitPorcelainLine(line);
    if (!parsed) continue;
    const { statusCode, filePath } = parsed;
    const fullPath = resolveGitStatusPath(snapshot, filePath);
    if (!fullPath) continue;

    if (statusCode === "??") {
      if (existsSync(fullPath)) actions.push({ kind: "remove", path: fullPath });
    } else if (statusCode.includes("M") || statusCode.includes("D") || statusCode.includes("T")) {
      actions.push({ kind: "checkout", path: fullPath });
    }
  }
  return actions;
}

function assertRestored(failures: string[]): void {
  if (failures.length > 0) {
    throw new RollbackError(
      `${failures.length} file(s) could not be restored: ${[...new Set(failures)].join(", ")}`,
    );
  }
}

/**
 * Executes an action inside an atomic rollback transaction envelope.
 */
export async function withAtomicRollback<T>(
  cwd: string,
  action: () => Promise<T>,
  options: {
    filesToTrack?: string[];
    shouldRollback?: (result: T) => boolean;
  } = {},
): Promise<T> {
  const snapshot = await createProjectSnapshot(cwd, options.filesToTrack);
  activeSnapshots.add(snapshot);

  try {
    const result = await action();
    if (options.shouldRollback?.(result)) {
      await restoreProjectSnapshot(snapshot);
    }
    return result;
  } catch (error) {
    try {
      await restoreProjectSnapshot(snapshot);
    } catch (restoreError) {
      throw new RollbackError(
        `${errorMessage(error)} (and the rollback failed: ${errorMessage(restoreError)})`,
        { cause: error },
      );
    }
    throw error;
  } finally {
    activeSnapshots.delete(snapshot);
  }
}
