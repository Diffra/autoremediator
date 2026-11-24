/**
 * The default handler for webhook-triggered remediation. It checks the event, loads the
 * repository's config, finds a workspace, runs the scan and answers a comment command at most once.
 */
import { handleCheckRun } from "./check-run-healing.js";
import { errorMessage } from "./errors.js";
import { postComment, type Octokit, type RepoRef } from "./issue-comments.js";
import { fetchRepoConfig } from "./repo-config.js";
import { runScanRemediation } from "./scan-run.js";
import { resolveTargetedRun, type TargetedRun } from "./targeted-run.js";
import {
  DEFAULT_REPO_CONFIG,
  type AutoremediatorRepoConfig,
  type DefaultRemediationHandlerOptions,
  type ParsedAuditFinding,
  type RemediationJobResult,
  type RemediationTriggerContext,
} from "./types.js";
import { cleanupWorkspace, openWorkspace, resolveCheckoutCwd } from "./workspace.js";

export type { DefaultRemediationHandlerOptions, ParsedAuditFinding };

export type RemediationHandler = (
  context: RemediationTriggerContext,
) => Promise<RemediationJobResult | void>;

const HANDLED_EVENTS = new Set<string>([
  "check_suite",
  "workflow_dispatch",
  "push",
  "check_run",
  "issue_comment",
  "dependabot_alert",
  "code_scanning_alert",
]);

export function createDefaultRemediationHandler(
  options: DefaultRemediationHandlerOptions,
): RemediationHandler {
  return (context) => handleRemediationEvent(context, options);
}

async function handleRemediationEvent(
  context: RemediationTriggerContext,
  options: DefaultRemediationHandlerOptions,
): Promise<RemediationJobResult | void> {
  if (!HANDLED_EVENTS.has(context.eventName)) {
    return;
  }

  const installationId = context.installationId ?? 0;
  const octokit = await options.octokitFactory(installationId);
  const repoRef = readRepoFromPayload(context.payload ?? {});
  const repoConfig = await loadRepoConfig(octokit, repoRef, options);

  // Special handler branch for check_run (PR auto-healing)
  if (context.eventName === "check_run") {
    return handleCheckRun({ context, octokit, repoRef, repoConfig, options });
  }

  const outcome = await resolveTargetedRun({ context, octokit, repoRef, repoConfig, options });
  if ("done" in outcome) return outcome.done;
  const targeted = outcome.run;
  const answersCommand = Boolean(targeted?.reply && repoRef);
  const answerFailed = (error: unknown) =>
    answerFailedCommand({ error, targeted, octokit, repoRef, options });

  const opened = await openWorkspace({
    options,
    context,
    repoRef,
    targetRef: resolveTargetRef(context.payload ?? {}),
  });
  if ("failure" in opened) {
    if (answersCommand) return answerFailed(opened.failure);
    throw opened.failure;
  }
  const { dir: workspaceDir, cleanup } = opened.workspace;

  let cwd: string;
  try {
    cwd = resolveCheckoutCwd(workspaceDir, repoConfig.cwd);
  } catch (error) {
    if (answersCommand) {
      await cleanup?.();
      return answerFailed(error);
    }
    throw error;
  }

  try {
    return await runScanRemediation({
      cwd,
      octokit,
      repoRef,
      repoConfig,
      targeted,
      installationToken: context.installationToken,
      options,
    });
  } catch (error) {
    // The error text can contain clone URLs, so it stays in the logs and out of the comment.
    if (answersCommand) return await answerFailed(error);
    throw error;
  } finally {
    await cleanupWorkspace(cleanup, options.onError);
  }
}

function readRepoFromPayload(payload: Record<string, unknown>): RepoRef | undefined {
  const repository = payload.repository;
  if (!repository || typeof repository !== "object") return undefined;
  const r = repository as Record<string, unknown>;
  const name = typeof r.name === "string" ? r.name : undefined;
  const owner = ownerLogin(r.owner);
  if (!owner || !name) return undefined;
  return { owner, repo: name };
}

function ownerLogin(ownerObj: unknown): string | undefined {
  if (typeof ownerObj === "string") {
    return ownerObj;
  }
  if (ownerObj && typeof ownerObj === "object") {
    return (ownerObj as Record<string, unknown>).login as string | undefined;
  }
  return undefined;
}

async function loadRepoConfig(
  octokit: Octokit,
  repoRef: RepoRef | undefined,
  options: DefaultRemediationHandlerOptions,
): Promise<AutoremediatorRepoConfig> {
  if (options.repoConfigProvider && repoRef) {
    return options.repoConfigProvider(repoRef.owner, repoRef.repo);
  }
  if (repoRef) {
    return fetchRepoConfig(octokit, repoRef.owner, repoRef.repo, options.onError);
  }
  // No repository in payload — use defaults
  return { ...DEFAULT_REPO_CONFIG };
}

/** The commit or branch the event is about, preferring the commit. */
function resolveTargetRef(payload: Record<string, unknown>): string | undefined {
  const checkSuite = payload.check_suite as Record<string, unknown> | undefined;
  const headSha = typeof checkSuite?.head_sha === "string" ? checkSuite.head_sha : payload.after;
  if (typeof headSha === "string") {
    return headSha;
  }
  if (typeof checkSuite?.head_branch === "string") {
    return checkSuite.head_branch;
  }
  return typeof payload.ref === "string" ? payload.ref.replace(/^refs\/heads\//, "") : undefined;
}

/**
 * A comment command gets exactly one reply. Once it has been given, failing the job would
 * make the queue run the command again and post again, so the failure is answered here and
 * the job ends as `partial` (never retried). The reply and the result carry no error text:
 * it can hold clone URLs with tokens, so it goes to the log, redacted.
 */
async function answerFailedCommand(params: {
  error: unknown;
  targeted: TargetedRun | undefined;
  octokit: Octokit;
  repoRef: RepoRef | undefined;
  options: DefaultRemediationHandlerOptions;
}): Promise<RemediationJobResult> {
  const { error, targeted, octokit, repoRef, options } = params;
  const message = redactTokens(errorMessage(error));
  void options.onError?.({
    timestamp: new Date().toISOString(),
    source: "github-app",
    level: "error",
    context: "remediation-handler.commentCommand",
    message: `Comment command failed: ${message}`,
    error: message,
  });
  if (targeted?.reply && repoRef) {
    await postComment(
      octokit,
      repoRef,
      targeted.reply.issueNumber,
      "**Autoremediator** could not finish this request. See the app logs for details.",
      options,
    );
  }
  return {
    status: "partial",
    reason: "The request failed and was answered; it is not retried",
  };
}

/** Hide the credential part of any `https://user:secret@host` URL in text bound for a log. */
function redactTokens(text: string): string {
  return text.replaceAll(/(https?:\/\/[^:/\s@]+:)[^@\s]+@/g, "$1***@");
}
