/**
 * Replies on issues and pull requests, and the permission check that gates comment commands.
 */
import { errorMessage } from "./errors.js";
import type { DefaultRemediationHandlerOptions } from "./types.js";

export type Octokit = Awaited<ReturnType<DefaultRemediationHandlerOptions["octokitFactory"]>>;

export type RepoRef = { owner: string; repo: string };

export async function postComment(
  octokit: Octokit,
  repo: RepoRef,
  issueNumber: number,
  body: string,
  options: DefaultRemediationHandlerOptions,
): Promise<void> {
  try {
    await octokit.issues.createComment({
      owner: repo.owner,
      repo: repo.repo,
      issue_number: issueNumber,
      body,
    });
  } catch (error) {
    const message = errorMessage(error);
    void options.onError?.({
      timestamp: new Date().toISOString(),
      source: "github-app",
      level: "warn",
      context: "remediation-handler.postComment",
      message: `Failed to post comment: ${message}`,
      error: message,
    });
  }
}

/** Only people who can already push may ask the app to change the repository. */
export async function hasWriteAccess(
  octokit: Octokit,
  repo: RepoRef,
  login: string,
): Promise<boolean> {
  try {
    const { data } = await octokit.repos.getCollaboratorPermissionLevel({
      owner: repo.owner,
      repo: repo.repo,
      username: login,
    });
    return data.permission === "admin" || data.permission === "write";
  } catch {
    return false;
  }
}
