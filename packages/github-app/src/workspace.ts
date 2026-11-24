/**
 * The directory a remediation run works in: a provided checkout, a fresh shallow clone of the
 * repository, or the current directory when the event names no repository.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve as resolvePath } from "node:path";

import { gitAuthEnvironment } from "./child-env.js";
import { errorMessage } from "./errors.js";
import type { RepoRef } from "./issue-comments.js";
import { runCommand } from "./run-command.js";
import type { DefaultRemediationHandlerOptions, RemediationTriggerContext } from "./types.js";

export interface Workspace {
  dir: string;
  cleanup: (() => Promise<void>) | undefined;
}

/** A workspace, or the error that stopped one from being made (to be answered or rethrown). */
export type WorkspaceOutcome = { workspace: Workspace } | { failure: unknown };

const BOT_NAME = "autoremediator[bot]";
const BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com";

export async function openWorkspace(params: {
  options: DefaultRemediationHandlerOptions;
  context: RemediationTriggerContext;
  repoRef: RepoRef | undefined;
  targetRef: string | undefined;
}): Promise<WorkspaceOutcome> {
  const { options, context, repoRef, targetRef } = params;

  if (options.checkoutProvider) {
    try {
      const checkout = await options.checkoutProvider({
        owner: repoRef?.owner ?? "unknown",
        repo: repoRef?.repo ?? "unknown",
        ref: targetRef,
        token: context.installationToken,
      });
      return { workspace: { dir: checkout.cwd, cleanup: checkout.cleanup } };
    } catch (error) {
      return { failure: error };
    }
  }
  if (repoRef) {
    return cloneWorkspace(repoRef, targetRef, context.installationToken);
  }
  return { workspace: { dir: process.cwd(), cleanup: undefined } };
}

/** The working directory inside the checkout; a configured `cwd` may not leave it. */
export function resolveCheckoutCwd(checkoutDir: string, configuredCwd: string | undefined): string {
  if (!configuredCwd) {
    return checkoutDir;
  }
  const cwd = resolvePath(checkoutDir, configuredCwd);
  const escaped = relative(checkoutDir, cwd);
  if (escaped.startsWith("..") || isAbsolute(escaped)) {
    throw new Error(`Configured cwd "${configuredCwd}" resolves outside the repository checkout.`);
  }
  return cwd;
}

export async function cleanupWorkspace(
  cleanup: (() => Promise<void>) | undefined,
  onError: DefaultRemediationHandlerOptions["onError"],
): Promise<void> {
  if (!cleanup) {
    return;
  }
  try {
    await cleanup();
  } catch (error) {
    const message = errorMessage(error);
    void onError?.({
      timestamp: new Date().toISOString(),
      source: "github-app",
      level: "warn",
      context: "remediation-handler.checkoutCleanup",
      message: `Failed to cleanup checkout workspace: ${message}`,
      error: message,
    });
  }
}

async function cloneWorkspace(
  repoRef: RepoRef,
  targetRef: string | undefined,
  token: string | undefined,
): Promise<WorkspaceOutcome> {
  const tempRepoDir = await mkdtemp(join(tmpdir(), "autoremediator-repo-"));
  const cleanup = async () => {
    await rm(tempRepoDir, { recursive: true, force: true }).catch(() => {});
  };

  // No token in the URL: it would be in the process list and in the clone's .git/config, which
  // the repository's own install scripts and tests can read.
  const cloneUrl = `https://github.com/${repoRef.owner}/${repoRef.repo}.git`;
  const cloneArgs = ["clone", "--depth", "1"];
  if (targetRef) {
    cloneArgs.push("--branch", targetRef);
  }
  cloneArgs.push(cloneUrl, tempRepoDir);

  try {
    const cloneRes = await runCommand(
      "git",
      cloneArgs,
      tempRepoDir,
      token ? gitAuthEnvironment(token) : {},
    );
    if (cloneRes.exitCode !== 0) {
      throw new Error(`git clone failed (code ${cloneRes.exitCode}): ${cloneRes.output}`);
    }
    await configureBotIdentity(tempRepoDir);
  } catch (cloneError) {
    if (process.env.NODE_ENV === "test" || !token) {
      await runCommand("git", ["init"], tempRepoDir);
      await configureBotIdentity(tempRepoDir);
    } else {
      await cleanup();
      return { failure: cloneError };
    }
  }
  return { workspace: { dir: tempRepoDir, cleanup } };
}

async function configureBotIdentity(dir: string): Promise<void> {
  await runCommand("git", ["config", "user.name", BOT_NAME], dir);
  await runCommand("git", ["config", "user.email", BOT_EMAIL], dir);
}
