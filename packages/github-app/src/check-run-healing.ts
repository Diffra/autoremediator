/**
 * `check_run` events: hand bot pull requests to the doctor, and heal failing checks on the
 * app's own pull requests.
 */
import { collectCheckRunLogs } from "./diagnostics/check-run-logs.js";
import { parseCheckRunLogs } from "./diagnostics/log-parser.js";
import { runBotPrDoctor } from "./doctor/bot-pr-doctor.js";
import { botKindOfBranch, isForkPullRequest } from "./doctor/bot-pr.js";
import { healPullRequest, regexRepairStrategy } from "./healing/pr-healer.js";
import type { Octokit, RepoRef } from "./issue-comments.js";
import type {
  AutoremediatorRepoConfig,
  DefaultRemediationHandlerOptions,
  RemediationJobResult,
  RemediationTriggerContext,
} from "./types.js";

type CheckRunParams = {
  context: RemediationTriggerContext;
  octokit: Octokit;
  repoRef: RepoRef | undefined;
  repoConfig: AutoremediatorRepoConfig;
  options: DefaultRemediationHandlerOptions;
};

export async function handleCheckRun(
  params: CheckRunParams,
): Promise<RemediationJobResult | undefined> {
  const { context, repoRef, repoConfig } = params;
  const checkRun = context.payload.check_run as Record<string, unknown> | undefined;
  const pullRequests =
    (checkRun?.pull_requests as Array<Record<string, unknown>> | undefined) ?? [];
  // Bot branches are the doctor's, even when a dependency name puts "autoremediator" in them.
  const botPr = pullRequests.find((p) => botKindOfBranch(headRefOf(p)) !== undefined);
  if (botPr) {
    return handleBotPullRequest(params, botPr, checkRun);
  }

  const pr = pullRequests.find((p) => {
    const ref = headRefOf(p);
    return ref.startsWith("autoremediator/") || ref.includes("autoremediator");
  });

  if (!pr || typeof pr.number !== "number" || !repoRef) {
    return undefined;
  }

  if (!repoConfig.enablePrAutoHealing) {
    return { status: "success", reason: "PR auto-healing disabled in repo config" };
  }

  return healAutoremediatorPullRequest(params, { pr, pullNumber: pr.number, repoRef, checkRun });
}

function headRefOf(pullRequest: Record<string, unknown>): string {
  const head = pullRequest.head as Record<string, unknown> | undefined;
  return typeof head?.ref === "string" ? head.ref : "";
}

async function handleBotPullRequest(
  params: CheckRunParams,
  botPr: Record<string, unknown>,
  checkRun: Record<string, unknown> | undefined,
): Promise<RemediationJobResult | undefined> {
  const { octokit, repoRef, repoConfig, options } = params;
  if (typeof botPr.number !== "number" || !repoRef || !checkRun) return undefined;
  // The webhook shows the head repository; the doctor checks again against the live pull request.
  if (isForkPullRequest(botPr)) {
    return { status: "success", reason: "Pull request comes from a fork" };
  }
  return runBotPrDoctor({
    octokit,
    owner: repoRef.owner,
    repo: repoRef.repo,
    pullNumber: botPr.number,
    checkRun,
    repoConfig,
    stateStore: options.stateStore,
    strategy: options.repairStrategy ?? regexRepairStrategy,
    selfAppId: options.selfAppId,
    logger: options.onError,
  });
}

async function healAutoremediatorPullRequest(
  params: CheckRunParams,
  target: {
    pr: Record<string, unknown>;
    pullNumber: number;
    repoRef: RepoRef;
    checkRun: Record<string, unknown> | undefined;
  },
): Promise<RemediationJobResult> {
  const { octokit, repoConfig, options } = params;
  const { pr, pullNumber, repoRef, checkRun } = target;
  const rawLogs = await collectCheckRunLogs(octokit, repoRef, checkRun, options.onError);

  const diagnostic = parseCheckRunLogs(rawLogs);
  const head = pr.head as Record<string, unknown> | undefined;
  const branchName = typeof head?.ref === "string" ? head.ref : "unknown";

  const healResult = await healPullRequest({
    octokit,
    owner: repoRef.owner,
    repo: repoRef.repo,
    pullNumber,
    branchName,
    checkRunName: typeof checkRun?.name === "string" ? checkRun.name : "CI Check",
    diagnostic,
    repoConfig,
    logger: options.onError,
  });

  return {
    status: healResult.healed ? "success" : "failed",
    reason: healResult.reason,
  };
}
