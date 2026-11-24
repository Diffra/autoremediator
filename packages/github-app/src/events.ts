import { codeScanningAlertTarget, dependabotAlertTarget } from "./alerts.js";
import { parseComment } from "./commands.js";
import { botKindOfBranch, isForkPullRequest } from "./doctor/bot-pr.js";
import type { AppStateStore } from "./state.js";
import type {
  DispatchResult,
  RemediationJobResult,
  RemediationTriggerContext,
  WebhookContext,
} from "./types.js";

interface DispatchOptions {
  stateStore?: AppStateStore;
  onRemediationRequested?: (
    context: RemediationTriggerContext,
  ) => Promise<RemediationJobResult | void> | RemediationJobResult | void;
  remediationTriggerTimeoutMs?: number;
}

function readAction(payload: Record<string, unknown>): string | undefined {
  const action = payload.action;
  return typeof action === "string" ? action : undefined;
}

function readInstallationId(payload: Record<string, unknown>): number | undefined {
  const installation = payload.installation;
  if (!installation || typeof installation !== "object") {
    return undefined;
  }

  const id = (installation as { id?: unknown }).id;
  return typeof id === "number" && Number.isFinite(id) ? id : undefined;
}

async function runWithTimeout(task: unknown, timeoutMs: number): Promise<void> {
  await Promise.race([
    Promise.resolve(task),
    new Promise<void>((_resolve, reject) => {
      setTimeout(() => reject(new Error(`Timed out after ${timeoutMs}ms`)), timeoutMs);
    }),
  ]);
}

type TriggerEvent = RemediationTriggerContext["eventName"];
type Payload = Record<string, unknown>;

const NOT_ACTIVE = (installationId: number): DispatchResult => ({
  status: "ignored",
  reason: `Installation ${installationId} is not active`,
});

/** The ignored result for an installation the app has marked inactive, if it is one. */
function inactiveInstallation(
  payload: Payload,
  options: DispatchOptions,
): DispatchResult | undefined {
  const installationId = readInstallationId(payload);
  if (
    installationId &&
    options.stateStore &&
    !options.stateStore.isInstallationActive(installationId)
  ) {
    return NOT_ACTIVE(installationId);
  }
  return undefined;
}

async function triggerRemediation(
  context: WebhookContext,
  payload: Payload,
  options: DispatchOptions,
  eventName: TriggerEvent,
): Promise<DispatchResult> {
  const inactive = inactiveInstallation(payload, options);
  if (inactive) return inactive;
  try {
    const triggerTask = options.onRemediationRequested?.({
      eventName,
      installationId: readInstallationId(payload),
      deliveryId: context.deliveryId,
      payload,
    });
    if (options.remediationTriggerTimeoutMs !== undefined && triggerTask !== undefined) {
      await runWithTimeout(triggerTask, options.remediationTriggerTimeoutMs);
    } else {
      await triggerTask;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown remediation trigger error";
    return { status: "handled", reason: `Remediation trigger failed: ${message}` };
  }
  return { status: "handled" };
}

type Handler = (
  context: WebhookContext,
  payload: Payload,
  options: DispatchOptions,
) => DispatchResult | Promise<DispatchResult>;

/** Install, uninstall, suspend and permission changes keep the app's own record of installations. */
const handleInstallation: Handler = (_context, payload, options) => {
  const action = readAction(payload);
  const installationId = readInstallationId(payload);
  if (!action) return { status: "ignored", reason: "Missing installation action" };
  if (!installationId) return { status: "ignored", reason: "Missing installation id" };

  if (action === "created" || action === "unsuspend" || action === "new_permissions_accepted") {
    options.stateStore?.markInstallationActive(installationId);
    return { status: "handled" };
  }
  if (action === "deleted" || action === "suspend") {
    options.stateStore?.markInstallationInactive(installationId);
    return { status: "handled" };
  }
  return { status: "ignored", reason: `Unsupported installation action: ${action}` };
};

const handleInstallationRepositories: Handler = (_context, payload, options) => {
  const action = readAction(payload);
  const installationId = readInstallationId(payload);
  if (!action) return { status: "ignored", reason: "Missing installation_repositories action" };
  if (!installationId) return { status: "ignored", reason: "Missing installation id" };
  const inactive = inactiveInstallation(payload, options);
  if (inactive) return inactive;
  if (action === "added" || action === "removed") return { status: "handled" };
  return { status: "ignored", reason: `Unsupported installation_repositories action: ${action}` };
};

const handleCheckSuite: Handler = (context, payload, options) => {
  const action = readAction(payload);
  if (action !== "requested" && action !== "rerequested") {
    return {
      status: "ignored",
      reason: `check_suite action not triggerable: ${action ?? "unknown"}`,
    };
  }
  return triggerRemediation(context, payload, options, "check_suite");
};

/** Only pushes to the default branch trigger a run. */
const handlePush: Handler = (context, payload, options) => {
  const inactive = inactiveInstallation(payload, options);
  if (inactive) return inactive;
  const ref = typeof payload.ref === "string" ? payload.ref : undefined;
  const repo = payload.repository;
  const branch =
    repo && typeof repo === "object" ? (repo as Record<string, unknown>).default_branch : undefined;
  const defaultBranch = typeof branch === "string" ? branch : undefined;
  if (!ref || !defaultBranch || ref !== `refs/heads/${defaultBranch}`) {
    return { status: "ignored", reason: `push to non-default branch (${ref ?? "unknown"})` };
  }
  return triggerRemediation(context, payload, options, "push");
};

const handleWorkflowDispatch: Handler = (context, payload, options) =>
  triggerRemediation(context, payload, options, "workflow_dispatch");

type PullRequestSummary = Record<string, unknown>;

const headRefOf = (pr: PullRequestSummary): string => {
  const head = pr.head as Record<string, unknown> | undefined;
  return typeof head?.ref === "string" ? head.ref : "";
};

/** Why a failed check run is not ours to act on, or undefined when it is. */
function checkRunIgnoredReason(pullRequests: PullRequestSummary[]): string | undefined {
  if (pullRequests.length === 0) return undefined;
  const isAutoremediatorPr = pullRequests.some((pr) => headRefOf(pr).includes("autoremediator"));
  // Dependabot and Renovate branches go to the bot PR doctor, which the repository must enable.
  // A pull request from a fork is dropped here already; the handler checks the rest.
  const isBotPr = pullRequests.some(
    (pr) => botKindOfBranch(headRefOf(pr)) !== undefined && !isForkPullRequest(pr),
  );
  if (isAutoremediatorPr || isBotPr) return undefined;
  const onlyForkedBot = pullRequests.every(
    (pr) => botKindOfBranch(headRefOf(pr)) !== undefined && isForkPullRequest(pr),
  );
  return onlyForkedBot
    ? "check_run failure on a bot pull request from a fork"
    : "check_run failure not on an autoremediator pull request branch";
}

const handleCheckRun: Handler = (context, payload, options) => {
  const action = readAction(payload);
  if (action !== "completed") {
    return { status: "ignored", reason: `check_run action not completed: ${action ?? "unknown"}` };
  }
  const checkRun = payload.check_run as Record<string, unknown> | undefined;
  const conclusion = checkRun?.conclusion as string | undefined;
  if (conclusion !== "failure") {
    return {
      status: "ignored",
      reason: `check_run conclusion not failure: ${conclusion ?? "unknown"}`,
    };
  }
  const pullRequests = (checkRun?.pull_requests as PullRequestSummary[] | undefined) ?? [];
  const reason = checkRunIgnoredReason(pullRequests);
  if (reason) return { status: "ignored", reason };
  return triggerRemediation(context, payload, options, "check_run");
};

const handleIssueComment: Handler = (context, payload, options) => {
  if (readAction(payload) !== "created") {
    return { status: "ignored", reason: "issue_comment action is not created" };
  }
  const comment = payload.comment as Record<string, unknown> | undefined;
  const user = comment?.user as Record<string, unknown> | undefined;
  const login = typeof user?.login === "string" ? user.login : "";
  // Never react to bots (including this app's own replies, which mention the commands).
  if (user?.type === "Bot" || login.endsWith("[bot]")) {
    return { status: "ignored", reason: "comment written by a bot" };
  }
  const body = typeof comment?.body === "string" ? comment.body : "";
  if (!parseComment(body)) {
    return { status: "ignored", reason: "comment has no autoremediator command" };
  }
  return triggerRemediation(context, payload, options, "issue_comment");
};

const handleAlert: Handler = (context, payload, options) => {
  const eventName = context.eventName as "dependabot_alert" | "code_scanning_alert";
  const action = readAction(payload);
  if (action !== "created" && action !== "reopened") {
    return {
      status: "ignored",
      reason: `${eventName} action not triggerable: ${action ?? "unknown"}`,
    };
  }
  const target =
    eventName === "dependabot_alert"
      ? dependabotAlertTarget(payload)
      : codeScanningAlertTarget(payload);
  if (!target) {
    return { status: "ignored", reason: `${eventName} does not name a CVE or GHSA advisory` };
  }
  return triggerRemediation(context, payload, options, eventName);
};

const HANDLERS: Record<string, Handler> = {
  ping: () => ({ status: "handled" }),
  installation: handleInstallation,
  installation_repositories: handleInstallationRepositories,
  check_suite: handleCheckSuite,
  push: handlePush,
  workflow_dispatch: handleWorkflowDispatch,
  check_run: handleCheckRun,
  issue_comment: handleIssueComment,
  dependabot_alert: handleAlert,
  code_scanning_alert: handleAlert,
};

export async function dispatchGitHubEvent(
  context: WebhookContext,
  payload: Payload,
  options: DispatchOptions = {},
): Promise<DispatchResult> {
  const handler = Object.hasOwn(HANDLERS, context.eventName)
    ? HANDLERS[context.eventName]
    : undefined;
  if (!handler) {
    return { status: "ignored", reason: `Unhandled event type: ${context.eventName}` };
  }
  return handler(context, payload, options);
}
