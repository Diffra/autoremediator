/**
 * Runs the remediation scan for one event: a full audit, or a filtered SARIF of the CVEs that
 * were named or selected by severity, then reports the result back where the request came from.
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { remediateFromScan, type ScanReport } from "autoremediator";

import { collectAuditFindings, selectCvesByMinimumSeverity } from "./audit-findings.js";
import { errorMessage } from "./errors.js";
import { postComment, type Octokit, type RepoRef } from "./issue-comments.js";
import { summarizeScanReport } from "./summary.js";
import type { TargetedRun } from "./targeted-run.js";
import type {
  AutoremediatorRepoConfig,
  DefaultRemediationHandlerOptions,
  RemediationJobResult,
} from "./types.js";

type ScanRemediateOptions = NonNullable<Parameters<typeof remediateFromScan>[1]>;
type ScanChangeRequestOptions = NonNullable<ScanRemediateOptions["changeRequest"]>;

interface ScanRunParams {
  cwd: string;
  octokit: Octokit;
  repoRef: RepoRef | undefined;
  repoConfig: AutoremediatorRepoConfig;
  targeted: TargetedRun | undefined;
  installationToken: string | undefined;
  options: DefaultRemediationHandlerOptions;
}

export async function runScanRemediation(params: ScanRunParams): Promise<RemediationJobResult> {
  const { cwd, repoConfig, targeted, options } = params;
  const shared = sharedScanOptions(params);
  const minimumSeverity = repoConfig.minimumSeverity;

  if (!targeted && minimumSeverity === "UNKNOWN") {
    const report = await remediateFromScan("", { ...shared, audit: true });
    return toRemediationJobResult(report);
  }

  const cveIds =
    targeted?.cveIds ??
    selectCvesByMinimumSeverity(
      options.auditFindingProvider
        ? await options.auditFindingProvider(cwd)
        : await collectAuditFindings(cwd),
      minimumSeverity,
    );
  if (cveIds.length === 0) {
    return { status: "success", reason: "No CVEs matched minimum severity filter" };
  }

  return runFilteredScan(params, shared, cveIds);
}

function sharedScanOptions(params: ScanRunParams) {
  const { cwd, repoConfig, targeted } = params;
  return {
    cwd,
    dryRun: targeted?.forceDryRun ?? repoConfig.dryRun,
    runTests: repoConfig.runTests,
    changeRequest: buildChangeRequest(params),
    allowMajorBumps: repoConfig.allowMajorBumps,
    denyPackages: repoConfig.denyPackages,
    allowPackages: repoConfig.allowPackages,
    constraints: repoConfig.constraints,
    patchConfidenceThresholds: repoConfig.patchConfidenceThresholds,
    dispositionPolicy: repoConfig.dispositionPolicy,
    containmentMode: repoConfig.containmentMode,
    escalationGraph: repoConfig.escalationGraph,
  };
}

function buildChangeRequest(params: ScanRunParams): ScanChangeRequestOptions | undefined {
  const { repoConfig, targeted, repoRef, installationToken } = params;
  const pullRequest = repoConfig.pullRequest ?? {};
  // A plan never changes anything; a fix asked for in a comment always ends in a reviewable pull request.
  const wantsPullRequest = targeted?.forceDryRun
    ? false
    : Boolean(pullRequest.enabled || targeted?.forcePullRequest);
  if (!wantsPullRequest) {
    return undefined;
  }
  return {
    enabled: true,
    provider: "github",
    grouping: pullRequest.grouping,
    repository:
      pullRequest.repository ?? (repoRef ? `${repoRef.owner}/${repoRef.repo}` : undefined),
    baseBranch: pullRequest.baseBranch,
    branchPrefix: pullRequest.branchPrefix,
    titlePrefix: pullRequest.titlePrefix,
    bodyFooter: pullRequest.bodyFooter,
    draft: pullRequest.draft,
    pushRemote: pullRequest.pushRemote,
    tokenEnvVar: pullRequest.tokenEnvVar,
    token: installationToken,
  };
}

async function runFilteredScan(
  params: ScanRunParams,
  shared: ReturnType<typeof sharedScanOptions>,
  cveIds: string[],
): Promise<RemediationJobResult> {
  const { octokit, repoRef, repoConfig, targeted, options } = params;
  const tempDir = await mkdtemp(join(tmpdir(), "autoremediator-ghapp-"));
  const filteredSarifPath = join(tempDir, "filtered-findings.sarif");

  try {
    await writeFile(
      filteredSarifPath,
      JSON.stringify(createSarifFromCves(cveIds), null, 2),
      "utf8",
    );

    const report = await remediateFromScan(filteredSarifPath, {
      ...shared,
      format: "sarif",
      audit: false,
    });

    const result = toRemediationJobResult(report);
    if (targeted?.reply && repoRef) {
      const dryRunDefaulted = targeted.reply.mode === "fix" && repoConfig.dryRun;
      await postComment(
        octokit,
        repoRef,
        targeted.reply.issueNumber,
        [
          summarizeScanReport(report, targeted.reply.mode),
          ...(dryRunDefaulted
            ? [
                "",
                "This repository defaults to dry runs; this request opened a pull request anyway because you asked for it.",
              ]
            : []),
        ].join("\n"),
        options,
      );
      // The summary is posted. A `failed` result would make the queue run the command again
      // and post it again, so it is reported as `partial` instead.
      if (result.status === "failed") return { ...result, status: "partial" };
    }
    return result;
  } finally {
    await removeTempDir(tempDir, options);
  }
}

async function removeTempDir(
  tempDir: string,
  options: DefaultRemediationHandlerOptions,
): Promise<void> {
  try {
    await rm(tempDir, { recursive: true, force: true });
  } catch (error) {
    const message = errorMessage(error);
    void options.onError?.({
      timestamp: new Date().toISOString(),
      source: "github-app",
      level: "warn",
      context: "remediation-handler.sarifCleanup",
      message: `Failed to remove temporary directory ${tempDir}: ${message}`,
      error: message,
    });
  }
}

function toRemediationJobResult(report: ScanReport): RemediationJobResult {
  if (report.status === "ok") {
    return { status: "success" };
  }

  if (report.status === "partial") {
    return {
      status: "partial",
      reason: `Scan completed with partial result (${report.successCount} success, ${report.failedCount} failed)`,
    };
  }

  return {
    status: "failed",
    reason: `Scan remediation failed (${report.failedCount} failed outcomes)`,
  };
}

function createSarifFromCves(cveIds: string[]): Record<string, unknown> {
  return {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "autoremediator-github-app",
            informationUri: "https://github.com/Diffra/autoremediator",
          },
        },
        results: cveIds.map((cveId) => ({
          ruleId: cveId,
          level: "warning",
          message: {
            text: `${cveId} was selected for remediation`,
          },
        })),
      },
    ],
  };
}
