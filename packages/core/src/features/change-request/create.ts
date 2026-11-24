/**
 * The change-request flow: group the reports, then for each group branch, commit, push and open
 * a request. A group that cannot go through becomes a result carrying the reason, never a throw.
 */
import { errorMessage } from "../../shared/errors.js";
import { safeExeca } from "../../shared/exec/safe-exec.js";
import { assertSafeGitRef } from "../../shared/git-ref.js";
import { redactSecrets } from "../../shared/redact.js";
import type { RemediationReport } from "../remediate/types.js";
import { commitMessage, deterministicBranchName } from "./branch.js";
import { inspectExistingBranch, withAuth } from "./existing-branch.js";
import type { ExistingBranch } from "./existing-branch.js";
import {
  detectCurrentBranch,
  ensureRepoHasChanges,
  ensureRepoHasStagedChanges,
  stageRunChanges,
} from "./git-repo.js";
import {
  commitIdentity,
  isValidRepositoryForProvider,
  resolveChangeRequestToken,
} from "./hosts.js";
import { openChangeRequest } from "./open-request.js";
import { buildPlan, groupReports, resolveGrouping, resolveProvider } from "./plan.js";
import type { ChangeRequestPlan } from "./plan.js";
import { createDestinationResolver } from "./push-destination.js";
import type { TokenDestination } from "./push-destination.js";
import type {
  ChangeRequestGrouping,
  ChangeRequestOptions,
  ChangeRequestProvider,
  ChangeRequestResult,
} from "./types.js";

const NO_CHANGES_ERROR = "No repository changes to include in change request.";

/** What is fixed for the whole run, whichever group is being handled. */
interface RunContext {
  cwd: string;
  options: ChangeRequestOptions;
  provider: ChangeRequestProvider;
  grouping: ChangeRequestGrouping;
  token: string | undefined;
  baseBranch: string;
  branchPrefix: string;
  pushRemote: string;
  destination: () => Promise<TokenDestination>;
}

/** The words of one request, with the caller's prefix and footer applied. */
interface RequestContent {
  plan: ChangeRequestPlan;
  title: string;
  body: string;
}

export async function createChangeRequestsForReports(params: {
  cwd: string;
  options: ChangeRequestOptions;
  reports: RemediationReport[];
}): Promise<ChangeRequestResult[]> {
  const { cwd, options, reports } = params;
  const provider = resolveProvider(options);
  const grouping = resolveGrouping(options);
  const groups = groupReports(reports, grouping);

  if (groups.length === 0) {
    return [];
  }

  const run = await prepareRun({ cwd, options, provider, grouping });
  const results: ChangeRequestResult[] = [];
  for (const group of groups) {
    results.push(await processGroup(run, group));
  }
  return results;
}

async function prepareRun(params: {
  cwd: string;
  options: ChangeRequestOptions;
  provider: ChangeRequestProvider;
  grouping: ChangeRequestGrouping;
}): Promise<RunContext> {
  const { cwd, options, provider, grouping } = params;
  const token = resolveChangeRequestToken(provider, options);

  // A caller-supplied branch reaches `git checkout`: it must not read as an option (git itself never names a branch "-...").
  if (options.baseBranch !== undefined) assertSafeGitRef("baseBranch", options.baseBranch);
  const baseBranch = options.baseBranch ?? (await detectCurrentBranch(cwd).catch(() => "main"));
  const branchPrefix = options.branchPrefix ?? "autoremediator";
  const pushRemote = options.pushRemote ?? "origin";
  if (options.pushRemote && !/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/.test(options.pushRemote)) {
    throw new Error(`Invalid pushRemote value: ${options.pushRemote}`);
  }

  const destination = createDestinationResolver({ cwd, provider, options, token, pushRemote });
  if (options.repository && !isValidRepositoryForProvider(provider, options.repository)) {
    throw new Error(`Invalid repository format: ${options.repository}`);
  }
  return {
    cwd,
    options,
    provider,
    grouping,
    token,
    baseBranch,
    branchPrefix,
    pushRemote,
    destination,
  };
}

function createContent(options: ChangeRequestOptions, plan: ChangeRequestPlan): RequestContent {
  const titlePrefix = options.titlePrefix?.trim().slice(0, 200);
  const bodyFooter = options.bodyFooter ? options.bodyFooter.slice(0, 2000) : undefined;
  const title = titlePrefix ? `${titlePrefix} ${plan.title}` : plan.title;
  const body = bodyFooter ? `${plan.body}\n\n${bodyFooter}` : plan.body;
  return { plan, title, body };
}

async function processGroup(
  run: RunContext,
  group: RemediationReport[],
): Promise<ChangeRequestResult> {
  const { cwd, options, provider, pushRemote } = run;
  const content = createContent(options, buildPlan(group));

  const hasChanges = await ensureRepoHasChanges(cwd).catch(() => false);
  if (!hasChanges) {
    return rejectedResult({ run, content, error: NO_CHANGES_ERROR });
  }

  const { pushToken, refusal: tokenRefusal } = await run.destination();
  if (tokenRefusal) {
    return rejectedResult({ run, content, error: tokenRefusal });
  }

  const { plan } = content;
  const branchName = deterministicBranchName(run.branchPrefix, plan.cveIds, plan.packageNames);
  const existing = await inspectExistingBranch(provider, cwd, pushRemote, branchName, pushToken);
  if (existing.foreign) {
    return rejectedResult({
      run,
      content,
      error: `Branch ${branchName} already exists with commits that autoremediator did not make; not overwriting it.`,
    });
  }

  return branchAndOpen({ run, group, content, branchName, existing, pushToken });
}

async function branchAndOpen(params: {
  run: RunContext;
  group: RemediationReport[];
  content: RequestContent;
  branchName: string;
  existing: ExistingBranch;
  pushToken: string | undefined;
}): Promise<ChangeRequestResult> {
  const { run, group, content, branchName, existing, pushToken } = params;
  const { cwd, options, provider, token } = run;
  let branchCreated = false;

  try {
    if ((provider === "bitbucket" || provider === "azure-devops") && !token) {
      throw new Error(
        `A token is required to create a ${provider} pull request: set changeRequest.token/tokenEnvVar or the provider's token environment variable.`,
      );
    }
    // -B: a re-run for the same findings restarts the branch from the current base.
    await safeExeca("git", ["checkout", "-B", branchName], { cwd, stdio: "pipe" });
    branchCreated = true;
    await stageRunChanges(cwd, group);

    const hasStaged = await ensureRepoHasStagedChanges(cwd);
    if (!hasStaged) {
      return rejectedResult({ run, content, error: NO_CHANGES_ERROR });
    }

    await commitStagedChanges(run, content.title, group);
    await pushBranch({ run, branchName, remoteSha: existing.remoteSha, pushToken });

    const url = await openChangeRequest({
      provider,
      cwd,
      repository: options.repository,
      head: branchName,
      base: run.baseBranch,
      title: content.title,
      body: content.body,
      draft: options.draft,
      token,
      githubApiUrl: options.githubApiUrl,
    });

    return {
      provider,
      grouping: run.grouping,
      repository: options.repository,
      branchName,
      title: content.title,
      body: content.body,
      created: true,
      ...(existing.remoteSha ? { updated: true } : {}),
      draft: options.draft,
      url,
      cveIds: content.plan.cveIds,
      packageNames: content.plan.packageNames,
    };
  } catch (error) {
    return rejectedResult({
      run,
      content,
      error: redactSecrets(errorMessage(error)),
      withDraft: true,
    });
  } finally {
    if (branchCreated) {
      await safeExeca("git", ["checkout", run.baseBranch], { cwd, stdio: "pipe" }).catch(() => {});
    }
  }
}

async function commitStagedChanges(
  run: RunContext,
  title: string,
  group: RemediationReport[],
): Promise<void> {
  const identity = commitIdentity(run.provider);
  await safeExeca(
    "git",
    [
      "-c",
      `user.name=${identity.name}`,
      "-c",
      `user.email=${identity.email}`,
      "commit",
      "-m",
      commitMessage(title, group),
    ],
    { cwd: run.cwd, stdio: "pipe" },
  );
}

/** A re-run replaces only the commit a previous run pushed, and only if nobody moved the branch since. */
async function pushBranch(params: {
  run: RunContext;
  branchName: string;
  remoteSha: string | undefined;
  pushToken: string | undefined;
}): Promise<void> {
  const { run, branchName, remoteSha, pushToken } = params;
  const { pushRemote } = run;
  const pushArgs = withAuth(
    run.provider,
    pushToken,
    remoteSha
      ? [
          "push",
          `--force-with-lease=refs/heads/${branchName}:${remoteSha}`,
          "-u",
          "--",
          pushRemote,
          branchName,
        ]
      : ["push", "-u", "--", pushRemote, branchName],
  );
  await safeExeca("git", pushArgs, { cwd: run.cwd, stdio: "pipe" });
}

/** A group that produced no request: the branch name is empty and `error` says why. */
function rejectedResult(params: {
  run: RunContext;
  content: RequestContent;
  error: string;
  withDraft?: boolean;
}): ChangeRequestResult {
  const { run, content, error, withDraft } = params;
  return {
    provider: run.provider,
    grouping: run.grouping,
    repository: run.options.repository,
    branchName: "",
    title: content.title,
    body: content.body,
    created: false,
    ...(withDraft ? { draft: run.options.draft } : {}),
    cveIds: content.plan.cveIds,
    packageNames: content.plan.packageNames,
    error,
  };
}
