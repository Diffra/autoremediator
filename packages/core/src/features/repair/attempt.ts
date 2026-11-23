import { detectPackageManager } from "../../infra/package-manager/index.js";
import { createProjectSnapshot, type ProjectSnapshot } from "../../infra/rollback/rollback.js";
import type { PackageManager } from "../../shared/types.js";
import type { CveDetails } from "../intelligence/types.js";
import type { LlmUsageMetrics, PatchResult } from "../remediate/types.js";
import type { PlanItem, PlanOptions } from "../runs/plan.js";
import { createWorktree, worktreeDiff, type Worktree } from "../runs/worktree.js";
import { applyPackageOverrideTool } from "../upgrade/apply-package-override/index.js";
import { applyVersionBumpTool } from "../upgrade/apply-version-bump.js";
import type { CheckName, VerificationResult, VerifyRequest } from "../verify/types.js";
import { verify } from "../verify/verifier.js";
import {
  loadAgentMemory,
  recipeStage,
  repairRounds,
  startAttempt,
  type Session,
} from "./attempt-stages.js";
import {
  findApplicableRecipes,
  type FindRecipesParams,
  type FoundRecipes,
} from "./recipe-attempt.js";
import type { RepairAgent, RepairBudget, RepairFailure, TranscriptEntry } from "./repair-agent.js";

export { commandsFor, failureOf } from "./attempt-stages.js";

/** Everything except `install`: the agent cannot change dependencies, and the upgrade already installed. */
export const ATTEMPT_CHECKS: readonly CheckName[] = [
  "scope",
  "policy",
  "supply-chain",
  "vuln-gone",
  "typecheck",
  "tests",
  "proof-of-fix",
];

export type AttemptStatus = "verified" | "rejected" | "failed";

export interface AttemptResult {
  status: AttemptStatus;
  /** Why it did not verify, or what the agent said it did. */
  reason: string;
  /** Times the agent was handed the verifier's findings. */
  rounds: number;
  /** The change, as a patch against the project's HEAD (only meaningful when verified). */
  diff: string;
  verification?: VerificationResult;
  changedFiles: string[];
  usage: LlmUsageMetrics[];
  transcript: TranscriptEntry[];
  /** `recipe:<id>` when a recipe made the project work, otherwise the agent's id. */
  agentId: string;
  /** What the verifier found wrong with the upgrade before anything was changed. */
  initialFailure?: RepairFailure;
}

export interface AttemptRequest {
  /** The project. */
  cwd: string;
  runId: string;
  attemptId: string;
  item: PlanItem;
  options: PlanOptions;
  advisories: readonly CveDetails[];
  /** Packages the plan knowingly leaves vulnerable. */
  expectedRemaining: readonly string[];
  /** Without one, only recipes are tried. */
  agent?: RepairAgent | undefined;
  budget: RepairBudget;
  signal: AbortSignal;
}

export interface AttemptDeps {
  createWorktree: (cwd: string, name: string) => Promise<Worktree>;
  /** Make the upgrade in the checkout and install it, without validating it. */
  applyUpgrade: (item: PlanItem, checkout: string, options: PlanOptions) => Promise<PatchResult>;
  verify: (request: VerifyRequest) => Promise<VerificationResult>;
  diff: (checkout: string) => Promise<string>;
  /** Recipes for the upgrade: the project's, the policy's recipe packages, and the checkout's installed packages. */
  findRecipes: (params: FindRecipesParams) => FoundRecipes;
}

export const defaultAttemptDeps: AttemptDeps = {
  createWorktree: (cwd, name) => createWorktree(cwd, name),
  async applyUpgrade(item, checkout, options) {
    const shared = {
      cwd: checkout,
      packageName: item.packageName,
      fromVersion: item.fromVersion,
      toVersion: item.toVersion,
      dryRun: false,
      policy: options.policy,
      // Only the upgrade and its install: whether the project still works is what the agent is for.
      runTests: false,
      installMode: options.constraints?.installMode,
      installPreferOffline: options.constraints?.installPreferOffline,
      workspace: options.constraints?.workspace,
      ...(options.packageManager
        ? { packageManager: options.packageManager as PackageManager }
        : {}),
    };
    return item.strategy === "version-bump"
      ? applyVersionBumpTool.execute({ ...shared, typecheck: false, breakingChangeRefactor: false })
      : applyPackageOverrideTool.execute(shared);
  },
  verify,
  diff: worktreeDiff,
  findRecipes: findApplicableRecipes,
};

/** The verification of an attempt's checkout against what the project was when it began. */
export function attemptVerifyRequest(params: {
  checkout: string;
  packageManager: PackageManager;
  options: PlanOptions;
  before: Pick<ProjectSnapshot, "fileSnapshots" | "isGit" | "gitStatusBefore">;
  advisories: readonly CveDetails[];
  expectedRemaining: readonly string[];
  checks?: readonly CheckName[];
}): VerifyRequest {
  const { options, before } = params;
  return {
    cwd: params.checkout,
    packageManager: params.packageManager,
    policy: options.policy,
    baseFiles: before.fileSnapshots,
    statusBefore: before.isGit ? (before.gitStatusBefore ?? []) : undefined,
    advisories: params.advisories,
    expectedRemaining: params.expectedRemaining,
    options: {
      ...(options.runTests === undefined ? {} : { runTests: options.runTests }),
      ...(options.typecheck === undefined ? {} : { typecheck: options.typecheck }),
      ...(options.proofOfFix === undefined ? {} : { proofOfFix: options.proofOfFix }),
      ...(options.requireProofOfFix === undefined
        ? {}
        : { requireProofOfFix: options.requireProofOfFix }),
      ...(options.reproductionTest ? { reproductionTest: options.reproductionTest } : {}),
      ...(options.constraints ? { constraints: options.constraints } : {}),
      allowSourceEdits: true,
    },
    checks: params.checks ?? ATTEMPT_CHECKS,
  };
}

/**
 * Try to make an upgrade work, in an isolated checkout. The upgrade is applied, the verifier says
 * what is wrong, and the agent is asked to fix it; each time it submits, the verifier judges
 * again, and its findings go back to the agent, up to the round limit. Nothing here touches the
 * project: the outcome is a patch that was verified, or a reason it was not.
 */
export async function runRepairAttempt(
  request: AttemptRequest,
  deps: AttemptDeps = defaultAttemptDeps,
): Promise<AttemptResult> {
  const { item, options } = request;
  const usage: LlmUsageMetrics[] = [];
  const transcript: TranscriptEntry[] = [];
  const { base, fail } = startAttempt(request, usage, transcript);

  const checkout = await deps.createWorktree(request.cwd, request.attemptId);
  try {
    const packageManager =
      (options.packageManager as PackageManager | undefined) ?? detectPackageManager(checkout.path);
    const before = await createProjectSnapshot(checkout.path);

    const memory = loadAgentMemory(request, transcript);

    const upgraded = await deps.applyUpgrade(item, checkout.path, options);
    if (!upgraded.applied) {
      return fail(
        "failed",
        `the upgrade could not be applied in a clean checkout: ${upgraded.message}`,
        0,
      );
    }

    const judge = (): Promise<VerificationResult> =>
      deps.verify(
        attemptVerifyRequest({
          checkout: checkout.path,
          packageManager,
          options,
          before,
          advisories: request.advisories,
          expectedRemaining: request.expectedRemaining,
        }),
      );

    const session: Session = {
      request,
      deps,
      checkoutPath: checkout.path,
      packageManager,
      usage,
      transcript,
      base,
      fail,
      judge,
      memory,
    };
    let verification = await judge();
    const previousRounds: string[] = [];

    if (!verification.passed) {
      const early = await recipeStage(session, verification);
      if (early) return early;
    }

    const repaired = await repairRounds(session, verification, previousRounds);
    if ("status" in repaired) return repaired;
    verification = repaired.verification;
    const { rounds } = repaired;

    if (!verification.passed) {
      const failed = verification.checks.find((check) => check.name === verification.failedCheck);
      return fail(
        "rejected",
        `the verifier still rejects it after ${rounds} round(s): ${verification.failedCheck}: ${failed?.message ?? ""}`,
        rounds,
        verification,
      );
    }

    return {
      ...base,
      status: "verified",
      reason: previousRounds.at(-1) ?? "the upgrade works as it is",
      rounds,
      diff: await deps.diff(checkout.path),
      verification,
      changedFiles: verification.changedFiles ?? [],
    };
  } finally {
    await checkout.remove();
  }
}
