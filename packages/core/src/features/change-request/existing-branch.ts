/** Inspecting a branch a re-run would reuse, so someone else's work is never overwritten. */
import { safeExeca } from "../../shared/exec/safe-exec.js";
import { buildPushAuthHeader, commitIdentity } from "./hosts.js";
import type { ChangeRequestProvider } from "./types.js";

export interface ExistingBranch {
  /** Where the branch already exists on the remote, if it does. */
  remoteSha?: string;
  /** Someone else's commits are on it (locally or remotely), so it must not be overwritten. */
  foreign: boolean;
}

/** `git` arguments that authenticate over HTTPS with the token, in the way the host expects. */
export function withAuth(
  provider: ChangeRequestProvider,
  token: string | undefined,
  args: string[],
): string[] {
  if (!token) return args;
  return ["-c", `http.extraheader=${buildPushAuthHeader(provider, token)}`, ...args];
}

/** Look at the branch a re-run would reuse before touching it. */
export async function inspectExistingBranch(
  provider: ChangeRequestProvider,
  cwd: string,
  remote: string,
  branch: string,
  token: string | undefined,
): Promise<ExistingBranch> {
  let foreign = false;
  const local = await safeExeca(
    "git",
    ["rev-parse", "--verify", "--quiet", `refs/heads/${branch}`],
    {
      cwd,
      stdio: "pipe",
    },
  ).catch(() => undefined);
  if (local?.stdout.trim()) {
    foreign = (await foreignCommits(cwd, `refs/heads/${branch}`, provider)) > 0;
  }

  const listed = await safeExeca(
    "git",
    withAuth(provider, token, ["ls-remote", "--heads", "--", remote, `refs/heads/${branch}`]),
    {
      cwd,
      stdio: "pipe",
    },
  ).catch(() => undefined);
  const remoteSha = /^([0-9a-f]{40})\s/.exec((listed?.stdout ?? "").trim())?.[1];
  if (remoteSha) {
    const fetched = await safeExeca(
      "git",
      withAuth(provider, token, ["fetch", "--", remote, `refs/heads/${branch}`]),
      {
        cwd,
        stdio: "pipe",
      },
    ).then(
      () => true,
      () => false,
    );
    // If we cannot read what is there, assume the worst rather than overwrite it.
    foreign = foreign || !fetched || (await foreignCommits(cwd, "FETCH_HEAD", provider)) > 0;
  }
  return { ...(remoteSha ? { remoteSha } : {}), foreign };
}

/**
 * Commits on `ref` that are not in HEAD and were not made by a previous change-request run
 * (our bot identity plus a `Fixes-CVE:` or `Autoremediator-Change:` trailer). Any such commit is somebody's work.
 */
async function foreignCommits(
  cwd: string,
  ref: string,
  provider: ChangeRequestProvider,
): Promise<number> {
  const result = await safeExeca("git", ["log", ref, "--not", "HEAD", "--format=%ae%x1f%B%x1e"], {
    cwd,
    stdio: "pipe",
  }).catch(() => ({ stdout: "" }));
  let foreign = 0;
  for (const entry of result.stdout.split("\u001e")) {
    const text = entry.trim();
    if (!text) continue;
    const [email = "", message = ""] = text.split("\u001f");
    if (
      email.trim() !== commitIdentity(provider).email ||
      !/^(?:Fixes-CVE|Autoremediator-Change): /m.test(message)
    ) {
      foreign += 1;
    }
  }
  return foreign;
}
