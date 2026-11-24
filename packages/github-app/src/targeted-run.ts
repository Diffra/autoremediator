/**
 * Work that names its advisories (a comment command or an alert) instead of scanning for them.
 */
import { codeScanningAlertTarget, dependabotAlertTarget } from "./alerts.js";
import { normalizeSeverity, SEVERITY_RANK } from "./audit-findings.js";
import { prepareCommentRun } from "./comment-command.js";
import type { Octokit, RepoRef } from "./issue-comments.js";
import type {
  AutoremediatorRepoConfig,
  DefaultRemediationHandlerOptions,
  RemediationJobResult,
  RemediationTriggerContext,
} from "./types.js";

export interface TargetedRun {
  cveIds: string[];
  forceDryRun?: boolean;
  forcePullRequest?: boolean;
  reply?: { issueNumber: number; mode: "plan" | "fix" };
}

/** Either the event is finished (`done`) or it continues, with a targeted run or a plain scan. */
export type TargetedOutcome =
  | { done: RemediationJobResult | undefined }
  | { run: TargetedRun | undefined };

export async function resolveTargetedRun(params: {
  context: RemediationTriggerContext;
  octokit: Octokit;
  repoRef: RepoRef | undefined;
  repoConfig: AutoremediatorRepoConfig;
  options: DefaultRemediationHandlerOptions;
}): Promise<TargetedOutcome> {
  const { context, octokit, repoRef, repoConfig, options } = params;
  const payload = context.payload ?? {};

  if (context.eventName === "issue_comment") {
    return prepareCommentRun(octokit, repoRef, payload, options);
  }
  if (context.eventName === "dependabot_alert" || context.eventName === "code_scanning_alert") {
    return alertRun(context.eventName, payload, repoConfig);
  }
  return { run: undefined };
}

function alertRun(
  eventName: "dependabot_alert" | "code_scanning_alert",
  payload: Record<string, unknown>,
  repoConfig: AutoremediatorRepoConfig,
): TargetedOutcome {
  const target =
    eventName === "dependabot_alert"
      ? dependabotAlertTarget(payload)
      : codeScanningAlertTarget(payload);
  if (!target) {
    return { done: undefined };
  }
  if (
    SEVERITY_RANK[normalizeSeverity(target.severity)] < SEVERITY_RANK[repoConfig.minimumSeverity]
  ) {
    return {
      done: { status: "success", reason: "Alert is below the configured minimum severity" },
    };
  }
  return { run: { cveIds: target.advisoryIds } };
}
