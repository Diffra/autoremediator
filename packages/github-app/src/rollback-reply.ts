/**
 * The reply to `/autoremediator rollback`: names the command that undoes a recorded run.
 */

import { botKindOfLogin } from "./doctor/bot-pr.js";
import type { Octokit, RepoRef } from "./issue-comments.js";

const RUN_TRAILER = /^Autoremediator-Run:[ \t]*(run_[0-9a-z]{20})[ \t]*$/gm;
const MAX_ROLLBACK_RUNS = 5;

/**
 * The comment for `/autoremediator rollback`: the exact command that undoes a recorded run. The
 * app never rolls back itself. Run ids are read from `Autoremediator-Run:` trailers and echoed
 * only if they match the run id format exactly.
 */
export async function rollbackReply(
  octokit: Octokit,
  repo: RepoRef,
  issueNumber: number,
  isPullRequest: boolean,
): Promise<string> {
  let runIds: Set<string>;
  try {
    runIds = await findRecordedRunIds(octokit, repo, issueNumber, isPullRequest);
  } catch {
    return "**Autoremediator** could not read this pull request to look for a recorded run. Try again, or revert its commits.";
  }

  const ids = [...runIds].slice(0, MAX_ROLLBACK_RUNS);
  if (ids.length === 0) {
    return [
      "**Autoremediator rollback**",
      "",
      "No `Autoremediator-Run:` trailer was found in this description or its commits, so there is no recorded run to roll back.",
      "To undo the change, revert its commits or close the pull request.",
    ].join("\n");
  }

  return [
    "**Autoremediator rollback**",
    "",
    "Autoremediator does not roll anything back from a comment. This records the following run(s); to undo one, run this in the checkout that made it:",
    "",
    "```sh",
    ...ids.map((id) => `autoremediator runs rollback ${id}`),
    "```",
    "",
    "It restores the files the run changed and reinstalls. A run is recorded in the `.autoremediator/runs` folder of the checkout where it ran: if this pull request was opened by the app from a temporary checkout, that record is gone, and reverting the pull request's commits is the way back.",
  ].join("\n");
}

async function findRecordedRunIds(
  octokit: Octokit,
  repo: RepoRef,
  issueNumber: number,
  isPullRequest: boolean,
): Promise<Set<string>> {
  const runIds = new Set<string>();
  const { data } = await octokit.issues.get({
    owner: repo.owner,
    repo: repo.repo,
    issue_number: issueNumber,
  });
  // Anyone can write a pull request description, and so can a package's changelog that
  // Dependabot copies into one, so only text the app itself wrote is believed.
  if (isAppAuthor(data.user?.login)) {
    for (const id of runIdsIn(data.body)) runIds.add(id);
  }

  if (runIds.size === 0 && isPullRequest) {
    const { data: commits } = await octokit.pulls.listCommits({
      owner: repo.owner,
      repo: repo.repo,
      pull_number: issueNumber,
      per_page: 100,
    });
    for (const commit of commits) {
      if (!isAppAuthor(commit.author?.login)) continue;
      for (const id of runIdsIn(commit.commit.message)) runIds.add(id);
    }
  }
  return runIds;
}

/** A bot account that is not one of the dependency bots, whose text copies third-party content. */
function isAppAuthor(login: string | null | undefined): boolean {
  if (!login?.toLowerCase().endsWith("[bot]")) return false;
  return botKindOfLogin(login) === undefined;
}

function runIdsIn(text: string | null | undefined): string[] {
  return [...(text ?? "").matchAll(RUN_TRAILER)].map((match) => match[1] ?? "").filter(Boolean);
}
