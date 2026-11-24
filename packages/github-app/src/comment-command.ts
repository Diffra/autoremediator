/**
 * Turns an `issue_comment` event into a run: checks the commenter, answers help, rollback and
 * retry requests itself, and otherwise names the advisories and mode to run.
 */
import { HELP_TEXT, parseComment, type ParsedCommand } from "./commands.js";
import { hasWriteAccess, postComment, type Octokit, type RepoRef } from "./issue-comments.js";
import { rollbackReply } from "./rollback-reply.js";
import type { TargetedRun } from "./targeted-run.js";
import type { DefaultRemediationHandlerOptions, RemediationJobResult } from "./types.js";

type CommentRunOutcome = { done: RemediationJobResult | undefined } | { run: TargetedRun };
type RunMode = "plan" | "fix";
type CommentContext = {
  octokit: Octokit;
  repo: RepoRef;
  issueNumber: number;
  options: DefaultRemediationHandlerOptions;
};

export async function prepareCommentRun(
  octokit: Octokit,
  repo: RepoRef | undefined,
  payload: Record<string, unknown>,
  options: DefaultRemediationHandlerOptions,
): Promise<CommentRunOutcome> {
  const comment = payload.comment as Record<string, unknown> | undefined;
  const issue = payload.issue as Record<string, unknown> | undefined;
  const issueNumber = issue?.number;
  const login = (comment?.user as Record<string, unknown> | undefined)?.login;
  const command = parseComment(typeof comment?.body === "string" ? comment.body : "");
  if (!command || !repo || typeof issueNumber !== "number" || typeof login !== "string") {
    return { done: undefined };
  }
  const ctx: CommentContext = { octokit, repo, issueNumber, options };

  if (!(await hasWriteAccess(octokit, repo, login))) {
    await noticeNoWriteAccess(ctx);
    return { done: { status: "success", reason: "Commenter lacks write access" } };
  }

  if (command.name === "rollback") {
    const isPullRequest = Boolean(issue?.pull_request);
    const reply = await rollbackReply(octokit, repo, issueNumber, isPullRequest);
    await postComment(octokit, repo, issueNumber, reply, options);
    return { done: { status: "success" } };
  }

  if (command.name === "help" || command.advisoryIds.length === 0) {
    const note =
      command.name !== "help" && command.advisoryIds.length === 0
        ? "That command needs at least one CVE or GHSA id.\n\n"
        : "";
    await postComment(octokit, repo, issueNumber, `${note}${HELP_TEXT}`, options);
    return { done: { status: "success" } };
  }

  const resolved = await resolveRunMode(ctx, command);
  if ("done" in resolved) {
    return resolved;
  }

  // Remember the request before running it, so a run that fails can still be retried.
  for (const id of command.advisoryIds) {
    options.stateStore?.recordRemediationMode(modeKey(repo, id), resolved.mode);
  }

  return {
    run: {
      cveIds: command.advisoryIds,
      forceDryRun: resolved.mode === "plan",
      forcePullRequest: resolved.mode === "fix",
      reply: { issueNumber, mode: resolved.mode },
    },
  };
}

function modeKey(repo: RepoRef, id: string): string {
  return `${repo.owner}/${repo.repo}:${id}`.toLowerCase();
}

async function noticeNoWriteAccess(ctx: CommentContext): Promise<void> {
  const { octokit, repo, issueNumber, options } = ctx;
  // Anyone can comment, so this is answered once per thread, and not at all when there is no
  // state store to remember it in: otherwise every comment of a stranger would get a reply.
  const noticeKey = `no-write-access:${repo.owner}/${repo.repo}#${issueNumber}`.toLowerCase();
  if (options.stateStore?.claimNotice(noticeKey)) {
    await postComment(
      octokit,
      repo,
      issueNumber,
      "Autoremediator commands need write access to this repository.",
      options,
    );
  }
}

async function resolveRunMode(
  ctx: CommentContext,
  command: ParsedCommand,
): Promise<{ mode: RunMode } | { done: RemediationJobResult }> {
  if (command.name !== "retry") {
    return { mode: command.name === "fix" ? "fix" : "plan" };
  }

  const { octokit, repo, issueNumber, options } = ctx;
  // Retry runs each advisory the way it was last run in this repository. That history lives in
  // the state store, so without one there is nothing to repeat.
  const known = command.advisoryIds.map((id) => ({
    id,
    mode: options.stateStore?.getRemediationMode(modeKey(repo, id)),
  }));
  const unknown = known.filter((entry) => entry.mode === undefined).map((entry) => entry.id);
  if (unknown.length > 0) {
    await postComment(
      octokit,
      repo,
      issueNumber,
      `Nothing to retry for ${unknown.join(", ")}: no earlier \`plan\` or \`fix\` of it was recorded for this repository. Use \`/autoremediator plan\` or \`/autoremediator fix\` first.`,
      options,
    );
    return { done: { status: "success", reason: "Nothing to retry" } };
  }
  const modes = new Set(known.map((entry) => entry.mode));
  if (modes.size > 1) {
    await postComment(
      octokit,
      repo,
      issueNumber,
      "Those advisories were last run in different modes (plan and fix). Retry them in separate comments.",
      options,
    );
    return { done: { status: "success", reason: "Mixed retry modes" } };
  }
  return { mode: known[0]?.mode === "fix" ? "fix" : "plan" };
}
