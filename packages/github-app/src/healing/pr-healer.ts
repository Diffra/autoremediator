/**
 * Autonomous PR Auto-Healer
 *
 * Listens to failing CI check runs on autoremediator pull requests,
 * extracts diagnostics, fetches failing files via Octokit, applies targeted
 * repairs, and pushes healing commits to trigger fresh CI verification.
 */
import type { Octokit } from "@octokit/rest";

import type { DiagnosticFinding, ParsedDiagnostic } from "../diagnostics/log-parser.js";
import { errorMessage } from "../errors.js";
import type { AutoremediatorRepoConfig, ErrorLogger } from "../types.js";
import { repairFileContent } from "./file-repair.js";
import { listPullRequestChangedFiles } from "./pr-files.js";
import { repairBranchFiles } from "./repair-branch.js";
import type { RepairStrategy } from "./repair-strategy.js";

export { repairFileContent };

export interface HealPrOptions {
  octokit: Octokit;
  owner: string;
  repo: string;
  pullNumber: number;
  branchName: string;
  checkRunName: string;
  diagnostic: ParsedDiagnostic;
  repoConfig: AutoremediatorRepoConfig;
  logger?: ErrorLogger;
  /** How files are repaired (default: the pattern-based strategy). */
  strategy?: RepairStrategy;
}

export interface HealPrResult {
  healed: boolean;
  attempt: number;
  maxAttempts: number;
  actionTaken: "commented-human-review" | "applied-healing-commit" | "skipped";
  healedFiles?: string[];
  reason?: string;
}

// In-memory attempt tracker per repo+PR
const ATTEMPTS_MAP = new Map<string, number>();

export function getHealingAttemptKey(owner: string, repo: string, pullNumber: number): string {
  return `${owner}/${repo}#${pullNumber}`;
}

export function resetHealingAttempts(owner: string, repo: string, pullNumber: number): void {
  ATTEMPTS_MAP.delete(getHealingAttemptKey(owner, repo, pullNumber));
}

export function getHealingAttempts(owner: string, repo: string, pullNumber: number): number {
  return ATTEMPTS_MAP.get(getHealingAttemptKey(owner, repo, pullNumber)) || 0;
}

/** The default repair strategy: pattern-based edits for a few well-understood errors. */
export const regexRepairStrategy: RepairStrategy = {
  name: "regex",
  repair: ({ content, findings }) => repairFileContent(content, [...findings]),
};

export async function healPullRequest(options: HealPrOptions): Promise<HealPrResult> {
  const { owner, repo, pullNumber, branchName, checkRunName, diagnostic, repoConfig } = options;

  const maxAttempts = repoConfig.maxHealingAttempts ?? 3;
  const key = getHealingAttemptKey(owner, repo, pullNumber);
  const currentAttempts = ATTEMPTS_MAP.get(key) || 0;

  if (currentAttempts >= maxAttempts) {
    return escalateAtAttemptLimit(options, currentAttempts, maxAttempts);
  }

  // Increment attempt counter
  const nextAttempt = currentAttempts + 1;
  ATTEMPTS_MAP.set(key, nextAttempt);

  const findingsByFile = groupFindingsByFile(diagnostic);
  if (findingsByFile.size === 0) {
    return escalateUnlocalizedFailure(options, nextAttempt, maxAttempts);
  }

  const allowedFiles = await listAllowedFiles(options);

  const { healedFiles } = await repairBranchFiles({
    octokit: options.octokit,
    owner,
    repo,
    branchName,
    findingsByFile,
    allowedFiles,
    strategy: options.strategy ?? regexRepairStrategy,
    commitMessage: `fix(autoremediator): auto-heal ${checkRunName} diagnostics [attempt ${nextAttempt}]`,
    logger: options.logger,
    pullNumber,
  });

  if (healedFiles.length === 0) {
    return escalateUnrepairedFiles(options, nextAttempt, maxAttempts);
  }

  await announceHealingApplied(options, { healedFiles, nextAttempt, maxAttempts });
  return {
    healed: true,
    attempt: nextAttempt,
    maxAttempts,
    actionTaken: "applied-healing-commit",
    healedFiles,
    reason: `Applied healing commit for ${healedFiles.join(", ")}.`,
  };
}

/** Exceeded max healing attempts: escalate to human review. */
async function escalateAtAttemptLimit(
  options: HealPrOptions,
  currentAttempts: number,
  maxAttempts: number,
): Promise<HealPrResult> {
  const { branchName, checkRunName, diagnostic } = options;
  const commentBody =
    `### ⚠️ Autoremediator Auto-Healing Limit Reached\n\n` +
    `Check run **${checkRunName}** failed on \`${branchName}\` after **${maxAttempts}** automated healing attempt(s).\n\n` +
    `**Diagnostic Summary:**\n` +
    `\`\`\`\n${diagnostic.summary}\n\`\`\`\n\n` +
    `Label \`autoremediator/needs-human-review\` added. Manual intervention is required to complete this remediation.`;

  await commentAndLabel(options, commentBody, "pr-healer.maxAttempts.commentAndLabel");

  return {
    healed: false,
    attempt: currentAttempts,
    maxAttempts,
    actionTaken: "commented-human-review",
    reason: "Maximum healing attempts reached.",
  };
}

/** Cannot pinpoint broken files from the CI logs. */
async function escalateUnlocalizedFailure(
  options: HealPrOptions,
  attempt: number,
  maxAttempts: number,
): Promise<HealPrResult> {
  const { branchName, checkRunName, diagnostic } = options;
  const commentBody =
    `### ⚠️ Autoremediator Auto-Healing Unable to Localize Failure\n\n` +
    `Check run **${checkRunName}** failed on \`${branchName}\`, but no actionable file paths could be extracted from CI logs.\n\n` +
    `**Diagnostic Summary:**\n` +
    `\`\`\`\n${diagnostic.summary}\n\`\`\`\n\n` +
    `Label \`autoremediator/needs-human-review\` added.`;

  await commentAndLabel(options, commentBody, "pr-healer.localizeFailure.commentAndLabel");

  return {
    healed: false,
    attempt,
    maxAttempts,
    actionTaken: "commented-human-review",
    reason: "No actionable file paths found in CI diagnostics.",
  };
}

/** None of the heuristics could repair the files. */
async function escalateUnrepairedFiles(
  options: HealPrOptions,
  attempt: number,
  maxAttempts: number,
): Promise<HealPrResult> {
  const { branchName, checkRunName, diagnostic } = options;
  const commentBody =
    `### ⚠️ Autoremediator Auto-Healing Unsuccessful\n\n` +
    `Check run **${checkRunName}** failed on \`${branchName}\`. Automated repair heuristics were unable to resolve the diagnostic errors.\n\n` +
    `**Diagnostic Summary:**\n` +
    `\`\`\`\n${diagnostic.summary}\n\`\`\`\n\n` +
    `Label \`autoremediator/needs-human-review\` added.`;

  await commentAndLabel(options, commentBody, "pr-healer.unsuccessful.commentAndLabel");

  return {
    healed: false,
    attempt,
    maxAttempts,
    actionTaken: "commented-human-review",
    reason: "Diagnostic errors could not be safely repaired automatically.",
  };
}

async function announceHealingApplied(
  options: HealPrOptions,
  applied: { healedFiles: string[]; nextAttempt: number; maxAttempts: number },
): Promise<void> {
  const { owner, repo, pullNumber, branchName, checkRunName } = options;
  const commentBody =
    `### 🩹 Autoremediator Auto-Healing Applied (Attempt ${applied.nextAttempt}/${applied.maxAttempts})\n\n` +
    `Pushed automated repair commit to \`${branchName}\` addressing diagnostics from **${checkRunName}**:\n` +
    applied.healedFiles.map((f) => `- \`${f}\``).join("\n") +
    `\n\nCI check suite will re-run automatically.`;

  try {
    await options.octokit.issues.createComment({
      owner,
      repo,
      issue_number: pullNumber,
      body: commentBody,
    });
  } catch (error) {
    logWarning(options, {
      context: "pr-healer.applied.comment",
      message: `Failed to comment on PR #${pullNumber}: ${errorMessage(error)}`,
      error,
    });
  }
}

function groupFindingsByFile(diagnostic: ParsedDiagnostic): Map<string, DiagnosticFinding[]> {
  const fileFindingsMap = new Map<string, DiagnosticFinding[]>();
  for (const finding of diagnostic.findings) {
    if (finding.filePath) {
      const existing = fileFindingsMap.get(finding.filePath) ?? [];
      existing.push(finding);
      fileFindingsMap.set(finding.filePath, existing);
    }
  }
  return fileFindingsMap;
}

/**
 * CI output names the files, and anything running in the job can print it, so only files this
 * pull request itself changed may be repaired.
 */
async function listAllowedFiles(options: HealPrOptions): Promise<Set<string>> {
  const { octokit, owner, repo, pullNumber } = options;
  try {
    return await listPullRequestChangedFiles(octokit, { owner, repo, pullNumber });
  } catch (error) {
    logWarning(options, {
      context: "pr-healer.listFiles",
      message: `Failed to list the files of PR #${pullNumber}: ${errorMessage(error)}`,
      error,
    });
    return new Set<string>();
  }
}

/** Post the escalation comment and add the review label; a failure is logged, not thrown. */
async function commentAndLabel(
  options: HealPrOptions,
  commentBody: string,
  context: string,
): Promise<void> {
  const { octokit, owner, repo, pullNumber } = options;
  try {
    await octokit.issues.createComment({
      owner,
      repo,
      issue_number: pullNumber,
      body: commentBody,
    });
    await octokit.issues.addLabels({
      owner,
      repo,
      issue_number: pullNumber,
      labels: ["autoremediator/needs-human-review"],
    });
  } catch (error) {
    logWarning(options, {
      context,
      message: `Failed to comment/label PR #${pullNumber}: ${errorMessage(error)}`,
      error,
    });
  }
}

function logWarning(
  options: HealPrOptions,
  warning: { context: string; message: string; error: unknown },
): void {
  void options.logger?.({
    timestamp: new Date().toISOString(),
    source: "github-app",
    level: "warn",
    context: warning.context,
    message: warning.message,
    error: errorMessage(warning.error),
    details: { owner: options.owner, repo: options.repo, pullNumber: options.pullNumber },
  });
}
