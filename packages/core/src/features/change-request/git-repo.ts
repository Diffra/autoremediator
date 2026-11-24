/** Questions put to the local git repository, and staging of what a run produced. */
import { existsSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

import { safeExeca } from "../../shared/exec/safe-exec.js";
import type { RemediationReport } from "../remediate/types.js";

export async function stageRunChanges(cwd: string, reports: RemediationReport[]): Promise<void> {
  // Stage modifications to tracked files only; never sweep up unrelated untracked files.
  await safeExeca("git", ["add", "-u"], { cwd, stdio: "pipe" });
  // New artifacts the run itself produced (generated patch files) are staged explicitly.
  const produced = new Set<string>();
  for (const report of reports) {
    for (const result of report.results) {
      if (!result.patchFilePath) continue;
      const abs = isAbsolute(result.patchFilePath)
        ? result.patchFilePath
        : resolve(cwd, result.patchFilePath);
      const rel = relative(cwd, abs);
      if (rel.startsWith("..") || isAbsolute(rel) || !existsSync(abs)) continue;
      produced.add(rel);
    }
  }
  if (produced.size > 0) {
    await safeExeca("git", ["add", "--", ...produced], { cwd, stdio: "pipe" });
  }
}

export async function detectCurrentBranch(cwd: string): Promise<string> {
  const result = await safeExeca("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
    cwd,
    stdio: "pipe",
  });
  return result.stdout.trim();
}

export async function ensureRepoHasChanges(cwd: string): Promise<boolean> {
  const diff = await safeExeca("git", ["status", "--porcelain"], {
    cwd,
    stdio: "pipe",
  });
  return diff.stdout.trim().length > 0;
}

export async function readOriginUrl(cwd: string): Promise<string> {
  const result = await safeExeca("git", ["config", "--get", "remote.origin.url"], {
    cwd,
    stdio: "pipe",
  }).catch(() => ({ stdout: "" }));
  return result.stdout.trim();
}

/** The URL a named remote pushes to, as configured (before any `insteadOf` rewriting). */
export async function readRemoteUrl(cwd: string, remote: string): Promise<string> {
  for (const key of [`remote.${remote}.pushurl`, `remote.${remote}.url`]) {
    const result = await safeExeca("git", ["config", "--get", key], { cwd, stdio: "pipe" }).catch(
      () => ({ stdout: "" }),
    );
    if (result.stdout.trim()) return result.stdout.trim();
  }
  return "";
}

export async function detectRepoFromRemote(cwd: string): Promise<string | undefined> {
  const url = await readOriginUrl(cwd);
  const match = /[:/]([^/]+)\/([^/]+?)(?:\.git)?$/.exec(url);
  if (match) {
    return `${match[1]}/${match[2]}`;
  }
  return undefined;
}

export async function ensureRepoHasStagedChanges(cwd: string): Promise<boolean> {
  const result = await safeExeca("git", ["diff", "--cached", "--name-only"], {
    cwd,
    stdio: "pipe",
  }).catch(() => ({ stdout: "" }));
  return result.stdout.trim().length > 0;
}
