/**
 * Applying half of apply-version-bump: write the new range, install, validate, and put the
 * original manifest back (and reinstall) whenever a step fails.
 */
import { readFileSync, writeFileSync } from "node:fs";

import { errorMessage } from "../../shared/errors.js";
import { safeExecaCommand } from "../../shared/exec/safe-exec-command.js";
import { LONG_RUNNING_TIMEOUT_MS } from "../../shared/timeouts.js";
import type { PatchResult } from "../remediate/types.js";
import type { ProofOfFixVerification } from "../verify/types.js";
import { serializeManifest } from "./manifest-format.js";
import type { VersionBumpInput } from "./version-bump-input.js";
import type { VersionBumpPlan } from "./version-bump-plan.js";
import { runNegativeProofPhase, runPositiveProofPhase } from "./version-bump-proof.js";
import { shouldAttemptRefactor, validateUpgrade } from "./version-bump-validation.js";
import type { ValidationOutcome } from "./version-bump-validation.js";

/** Runs a planned bump. The caller holds the repo lock. */
export async function runVersionBump(
  input: VersionBumpInput,
  plan: VersionBumpPlan,
): Promise<PatchResult> {
  const negative = await runNegativeProofPhase(input);
  if (negative.kind === "result") {
    return negative.result;
  }

  // Write updated package.json, keeping the file's own formatting; a failed upgrade puts the
  // original bytes back, so nothing about it shows up in a diff.
  const originalManifest = readFileSync(plan.pkgPath, "utf8");
  plan.pkgJson[plan.depField]![input.packageName] = plan.newRange;
  writeFileSync(plan.pkgPath, serializeManifest(originalManifest, plan.pkgJson), "utf8");

  const installFailure = await installOrRevert(input, plan, originalManifest);
  if (installFailure) {
    return installFailure;
  }

  const validation = await validateUpgrade(input, plan);
  const rollback = (): Promise<void> => restoreManifestAndReinstall(input, plan, originalManifest);

  if (!validation.passed) {
    await rollback();
    return createValidationFailure(input, plan, validation);
  }

  const positive = await runPositiveProofPhase({
    input,
    state: negative.state,
    validationPassed: validation.passed,
    rollback,
  });
  if (positive.kind === "result") {
    return positive.result;
  }

  return createSuccessResult({ input, plan, validation, proofOfFix: positive.verification });
}

async function runPackageManagerCommand(cwd: string, command: string[]): Promise<void> {
  await safeExecaCommand(command, {
    timeoutMs: LONG_RUNNING_TIMEOUT_MS,
    cwd,
    stdio: "pipe",
  });
}

async function installOrRevert(
  input: VersionBumpInput,
  plan: VersionBumpPlan,
  originalManifest: string,
): Promise<PatchResult | undefined> {
  try {
    await runPackageManagerCommand(input.cwd, plan.commands.install);
    return undefined;
  } catch (err) {
    // Revert the package.json change on install failure
    writeFileSync(plan.pkgPath, originalManifest, "utf8");

    const message = errorMessage(err);
    return {
      packageName: input.packageName,
      strategy: "version-bump",
      fromVersion: input.fromVersion,
      toVersion: input.toVersion,
      applied: false,
      dryRun: false,
      unresolvedReason: "install-failed",
      message: `${plan.commands.install.join(" ")} failed after updating "${input.packageName}" to ${input.toVersion}. Reverted. Error: ${message}`,
    };
  }
}

async function restoreManifestAndReinstall(
  input: VersionBumpInput,
  plan: VersionBumpPlan,
  originalManifest: string,
): Promise<void> {
  writeFileSync(plan.pkgPath, originalManifest, "utf8");

  try {
    await runPackageManagerCommand(input.cwd, plan.commands.install);
  } catch {
    // Best effort: the manifest is already restored, and the failure being reported is the
    // upgrade's, not the reinstall's.
  }
}

function createValidationFailure(
  input: VersionBumpInput,
  plan: VersionBumpPlan,
  validation: ValidationOutcome,
): PatchResult {
  const { packageName, toVersion } = input;
  const failureMessage = validation.error || "Unknown validation error";
  const failurePrefix = validation.isTypecheck
    ? `TypeCheck validation failed (${plan.commands.typecheck.join(" ")})`
    : `${plan.commands.test.join(" ")} failed`;

  return {
    packageName,
    strategy: "version-bump",
    fromVersion: input.fromVersion,
    toVersion,
    applied: false,
    dryRun: false,
    unresolvedReason: shouldAttemptRefactor(input, plan)
      ? "breaking-change-unresolved"
      : "validation-failed",
    message: `${failurePrefix} after upgrading "${packageName}" to ${toVersion}. Rolled back to ${plan.currentRange}. Error: ${failureMessage}`,
  };
}

async function createSuccessResult(params: {
  input: VersionBumpInput;
  plan: VersionBumpPlan;
  validation: ValidationOutcome;
  proofOfFix: ProofOfFixVerification | undefined;
}): Promise<PatchResult> {
  const { input, plan, validation, proofOfFix } = params;
  const { packageName, fromVersion, toVersion } = input;
  const refactoredFiles = validation.refactoredFiles;

  if (refactoredFiles && refactoredFiles.length > 0) {
    return {
      packageName,
      strategy: "breaking-change-refactor",
      fromVersion,
      toVersion,
      applied: true,
      dryRun: false,
      refactoredFiles,
      proofOfFix,
      message: `Upgraded "${packageName}" from ${fromVersion} to ${toVersion} and refactored ${refactoredFiles.length} call-site file(s) across breaking API changes.`,
    };
  }

  const dedupeNote = await runDedupe(input, plan);
  const passedTests = input.runTests ? ` and passed ${plan.commands.test.join(" ")}` : "";
  return {
    packageName,
    strategy: "version-bump",
    fromVersion,
    toVersion,
    applied: true,
    dryRun: false,
    proofOfFix,
    message: `Successfully upgraded "${packageName}" from ${fromVersion} to ${toVersion} in ${plan.depField}, then ran ${plan.commands.install.join(" ")}${passedTests}.${dedupeNote}`,
  };
}

/** Dedupe is best effort: a failure becomes a note on the result, not a rollback. */
async function runDedupe(input: VersionBumpInput, plan: VersionBumpPlan): Promise<string> {
  const dedupeCommand = plan.commands.dedupe;
  if (dedupeCommand.length === 0) {
    return "";
  }
  try {
    await runPackageManagerCommand(input.cwd, dedupeCommand);
    return "";
  } catch (err) {
    return ` Dedupe warning: ${dedupeCommand.join(" ")} failed (${errorMessage(err)}).`;
  }
}
