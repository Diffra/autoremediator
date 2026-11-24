/**
 * The apply-patch-file run: check the input, then under the repo lock write the patch, prove the
 * exploit, apply, reinstall, test, prove the fix, and record the manifest. Any failing step rolls
 * the patch back and returns its result.
 */
import { withRepoLock } from "../../../infra/repo-lock.js";
import { errorMessage } from "../../../shared/errors.js";
import type { ProofOfFixPhaseResult } from "../../verify/types.js";
import type { PatchArtifact } from "../types.js";
import {
  applyPatchToProject,
  runPatchPackageInstall,
  runPatchValidationTests,
} from "./apply-steps.js";
import type { PatchRun } from "./failure.js";
import { writePatchManifest, type ValidationResult } from "./helpers.js";
import type { ApplyPatchFileInput } from "./input-schema.js";
import { writePatchFiles } from "./patch-write.js";
import { preparePatchPlan, type PatchPlan } from "./preflight.js";
import {
  buildProofOfFixVerification,
  prepareProofOfFix,
  runNegativeProofStep,
  runPositiveProofStep,
  type ProofOfFixSettings,
} from "./proof-steps.js";
import type { ApplyPatchFileResult } from "./types.js";

export async function applyPatchFile(input: ApplyPatchFileInput): Promise<ApplyPatchFileResult> {
  const { packageName, vulnerableVersion, cwd, dryRun } = input;
  try {
    const prepared = await preparePatchPlan(input);
    if (!prepared.ok) return prepared.result;
    const plan = prepared.value;

    if (dryRun) return dryRunResult(plan, input);

    return await withRepoLock(cwd, async () => applyUnderLock(plan, input));
  } catch (err) {
    const message = errorMessage(err);
    return {
      success: false,
      packageName,
      vulnerableVersion,
      applied: false,
      dryRun,
      message: `Failed to apply patch file: ${message}`,
      error: `Failed to apply patch file: ${message}`,
    };
  }
}

function dryRunResult(plan: PatchPlan, input: ApplyPatchFileInput): ApplyPatchFileResult {
  return {
    success: true,
    packageName: input.packageName,
    vulnerableVersion: input.vulnerableVersion,
    applied: false,
    dryRun: true,
    message: `[DRY RUN] Would write and configure patch at ${plan.patchFilePath}.`,
    patchFilePath: plan.patchFilePath,
    manifestFilePath: plan.manifestFilePath,
    patchPath: plan.patchFilePath,
    patchArtifact: plan.baseArtifact,
    validationPhases: plan.validationPhases,
  };
}

async function applyUnderLock(
  plan: PatchPlan,
  input: ApplyPatchFileInput,
): Promise<ApplyPatchFileResult> {
  const written = await writePatchFiles(plan, input.cwd);
  const run: PatchRun = {
    cwd: input.cwd,
    packageName: input.packageName,
    vulnerableVersion: input.vulnerableVersion,
    patchFilePath: plan.patchFilePath,
    manifestFilePath: plan.manifestFilePath,
    patchMode: written.patchMode,
    installCommand: plan.installCommand,
    packageJsonSnapshot: written.packageJsonSnapshot,
    artifact: written.artifact,
    validationPhases: plan.validationPhases,
  };

  const settings = await prepareProofOfFix(input, written.patchesDirPath);
  const negative = await runNegativeProofStep(run, settings);
  if (!negative.ok) return negative.result;

  const applied = await applyPatchToProject({ run, pm: plan.pm, patchContent: plan.selectedPatch });
  if (!applied.ok) return applied.result;

  const installed = await runPatchPackageInstall(run);
  if (!installed.ok) return installed.result;

  let validation: ValidationResult | undefined;
  if (input.validateWithTests) {
    const tested = await runPatchValidationTests(run, plan.testCommand);
    if (!tested.ok) return tested.result;
    validation = tested.value;
  }

  const positive = await runPositiveProofStep(run, settings);
  if (!positive.ok) return positive.result;

  return finalizeApplied({
    run,
    input,
    settings,
    validation,
    proofPhases: { negative: negative.value, positive: positive.value },
  });
}

async function finalizeApplied(params: {
  run: PatchRun;
  input: ApplyPatchFileInput;
  settings: ProofOfFixSettings;
  validation: ValidationResult | undefined;
  proofPhases: {
    negative: ProofOfFixPhaseResult | undefined;
    positive: ProofOfFixPhaseResult | undefined;
  };
}): Promise<ApplyPatchFileResult> {
  const { run, input, settings, validation, proofPhases } = params;
  const proofOfFix = buildProofOfFixVerification({ settings, ...proofPhases, validation });

  const finalArtifact: PatchArtifact = {
    ...run.artifact,
    applied: true,
    dryRun: false,
    reproductionTest: input.reproductionTest,
    reproductionTestPath: settings.reproductionTestPath,
    validationPhases: run.validationPhases,
    proofOfFix,
  };
  await writePatchManifest(run.manifestFilePath, finalArtifact);

  return {
    success: true,
    packageName: run.packageName,
    vulnerableVersion: run.vulnerableVersion,
    applied: true,
    dryRun: false,
    message: `Patch applied successfully for ${run.packageName}@${run.vulnerableVersion}.`,
    patchFilePath: run.patchFilePath,
    manifestFilePath: run.manifestFilePath,
    patchPath: run.patchFilePath,
    patchMode: run.patchMode,
    postinstallConfigured: run.patchMode === "patch-package",
    patchArtifact: finalArtifact,
    validation,
    validationPhases: run.validationPhases,
    proofOfFix,
  };
}
