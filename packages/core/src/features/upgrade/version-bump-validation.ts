/**
 * Validation half of apply-version-bump: run the project's tests and typecheck after the
 * install and, when allowed, let the call-site refactor try to repair a failure.
 */
import { findPackageCallSites } from "../refactor/call-site-finder.js";
import { refactorConsumerCallSites, revertRefactorSnapshots } from "../refactor/codemods.js";
import { runCommandCheck } from "../verify/command-check.js";
import type { VersionBumpInput } from "./version-bump-input.js";
import type { VersionBumpPlan } from "./version-bump-plan.js";

export interface ValidationOutcome {
  passed: boolean;
  error?: string;
  isTypecheck?: boolean;
  /** Set when a refactor repaired a failing validation. */
  refactoredFiles?: string[];
}

export function shouldAttemptRefactor(input: VersionBumpInput, plan: VersionBumpPlan): boolean {
  return Boolean(
    input.breakingChangeRefactor ?? plan.loadedPolicy.constraints?.enableBreakingChangeRefactor,
  );
}

/** Validates the upgrade, trying one call-site refactor if validation fails and it is enabled. */
export async function validateUpgrade(
  input: VersionBumpInput,
  plan: VersionBumpPlan,
): Promise<ValidationOutcome> {
  const validationResult = await runValidationSteps(input, plan);
  if (validationResult.passed || !shouldAttemptRefactor(input, plan)) {
    return validationResult;
  }

  const refactoredFiles = await tryRefactorCallSites(input, plan, validationResult.error);
  if (refactoredFiles) {
    return { passed: true, refactoredFiles };
  }
  return validationResult;
}

async function runValidationSteps(
  input: VersionBumpInput,
  plan: VersionBumpPlan,
): Promise<ValidationOutcome> {
  const { cwd } = input;
  if (input.runTests) {
    const outcome = await runCommandCheck(plan.commands.test, cwd);
    if (!outcome.passed) return { passed: false, error: outcome.output };
  }
  if (plan.shouldTypecheck && plan.commands.typecheck.length > 0) {
    const outcome = await runCommandCheck(plan.commands.typecheck, cwd);
    if (!outcome.passed) return { passed: false, isTypecheck: true, error: outcome.output };
  }
  return { passed: true };
}

/** Returns the refactored files when the refactor made validation pass, otherwise undefined. */
async function tryRefactorCallSites(
  input: VersionBumpInput,
  plan: VersionBumpPlan,
  diagnosticError: string | undefined,
): Promise<string[] | undefined> {
  const { cwd, packageName, fromVersion, toVersion } = input;
  const callSites = findPackageCallSites(cwd, packageName);
  if (callSites.length === 0) return undefined;

  const refactorAttempt = await refactorConsumerCallSites({
    cwd,
    packageName,
    fromVersion,
    toVersion,
    diagnosticError: diagnosticError || "",
    callSites,
  });
  if (!refactorAttempt.applied) return undefined;

  const postRefactorValidation = await runValidationSteps(input, plan);
  if (postRefactorValidation.passed) {
    return refactorAttempt.refactoredFiles;
  }
  revertRefactorSnapshots(refactorAttempt.snapshots);
  return undefined;
}
