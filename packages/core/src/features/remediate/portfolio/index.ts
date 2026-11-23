import { errorMessage } from "../../../shared/errors.js";
import type { ScanReport } from "../contracts.js";
import { remediate } from "../index.js";
import { assertValidSimulationMode, buildSlaBreachSummary } from "../reporting.js";
import { remediateFromScan } from "../scan/index.js";
import type { RemediateOptions, RemediationReport } from "../types.js";
import { rankPortfolioTargets } from "./risk-score.js";
import type { PortfolioReport, PortfolioTarget, PortfolioTargetResult } from "./types.js";

function toTargetStatusFromRemediation(report: RemediationReport): "ok" | "partial" | "failed" {
  const failed = report.results.some((result) => !result.applied && !result.dryRun);
  const succeeded = report.results.some((result) => result.applied || result.dryRun);
  if (!failed) return "ok";
  return succeeded ? "partial" : "failed";
}

function normalizeTargetInput(target: PortfolioTarget): {
  cveId?: string;
  inputPath?: string;
  audit: boolean;
} {
  return {
    cveId: target.cveId?.trim() || undefined,
    inputPath: target.inputPath?.trim() || undefined,
    audit: target.audit ?? false,
  };
}

function validateTarget(target: PortfolioTarget, index: number): void {
  if (!target.cwd || typeof target.cwd !== "string") {
    throw new Error(`Invalid portfolio target at index ${index}: cwd is required.`);
  }

  const { cveId, inputPath, audit } = normalizeTargetInput(target);
  const hasScanInput = Boolean(inputPath) || audit;

  if (Boolean(cveId) === hasScanInput) {
    throw new Error(
      `Invalid portfolio target at index ${index}: provide exactly one mode (cveId OR inputPath/audit).`,
    );
  }
}

export async function remediatePortfolio(
  targets: PortfolioTarget[],
  options: RemediateOptions = {},
): Promise<PortfolioReport> {
  assertValidSimulationMode(options);
  const normalizedTargets = Array.isArray(targets) ? targets : [];

  if (normalizedTargets.length === 0) {
    throw new Error("Portfolio requires at least one target.");
  }

  for (const [index, target] of normalizedTargets.entries()) {
    validateTarget(target, index);
  }

  const executionTargets =
    options.campaignMode === true
      ? rankPortfolioTargets(normalizedTargets)
      : normalizedTargets.map((target) => ({ target, rank: undefined }));

  const results: PortfolioTargetResult[] = [];
  const changeRequests = [] as NonNullable<PortfolioReport["changeRequests"]>;
  let successCount = 0;
  let failedCount = 0;

  for (const executionTarget of executionTargets) {
    const threatRank = options.campaignMode === true ? executionTarget.rank : undefined;
    const result = await runPortfolioTarget(executionTarget.target, threatRank, options);
    results.push(result);
    if (result.changeRequests?.length) {
      changeRequests.push(...result.changeRequests);
    }
    if (result.status === "failed") {
      failedCount += 1;
    } else {
      successCount += 1;
    }
  }

  const overallStatus = overallStatusOf(failedCount, successCount);

  const allRemediationReports: RemediationReport[] = results.flatMap((r) => {
    if (r.remediationReport) return [r.remediationReport];
    const scan = r.scanReport as ScanReport | undefined;
    return scan?.reports ?? [];
  });

  return {
    schemaVersion: "1.0",
    status: overallStatus,
    generatedAt: new Date().toISOString(),
    targets: results,
    successCount,
    failedCount,
    changeRequests: changeRequests.length > 0 ? changeRequests : undefined,
    slaBreachSummary: buildSlaBreachSummary(allRemediationReports),
  };
}

function overallStatusOf(failedCount: number, successCount: number): "ok" | "partial" | "failed" {
  if (failedCount === 0) {
    return "ok";
  }
  return successCount > 0 ? "partial" : "failed";
}

/** Remediates one portfolio target; a failure becomes a failed result rather than aborting the rest. */
async function runPortfolioTarget(
  target: PortfolioTarget,
  threatRank: number | undefined,
  options: RemediateOptions,
): Promise<PortfolioTargetResult> {
  const { cveId, inputPath, audit } = normalizeTargetInput(target);
  const rank = threatRank === undefined ? {} : { threatRank };

  try {
    if (cveId) {
      const remediationReport = await remediate(cveId, {
        ...options,
        cwd: target.cwd,
        source: options.source,
      });
      return {
        target,
        status: toTargetStatusFromRemediation(remediationReport),
        ...rank,
        remediationReport,
        changeRequests: remediationReport.changeRequests,
      };
    }

    const scanReport = await remediateFromScan(inputPath ?? "", {
      ...options,
      cwd: target.cwd,
      audit,
      format: target.format,
      source: options.source,
    });
    return {
      target,
      status: scanReport.status,
      ...rank,
      scanReport,
      changeRequests: scanReport.changeRequests,
    };
  } catch (error) {
    return { target, status: "failed", ...rank, error: errorMessage(error) };
  }
}
