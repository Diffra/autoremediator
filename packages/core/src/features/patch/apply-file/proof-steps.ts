/**
 * The proof-of-fix steps of apply-patch-file: prepare the reproduction test, prove the exploit
 * works before the patch (negative), prove it fails after (positive), and assemble the verdict.
 */
import type { UnresolvedReason } from "../../../shared/types.js";
import {
  assembleProofOfFixVerification,
  prepareReproductionTestFile,
  runProofOfFixPhase,
} from "../../verify/proof-of-fix/runner.js";
import type {
  PatchValidationPhase,
  ProofOfFixPhaseResult,
  ProofOfFixVerification,
} from "../../verify/types.js";
import { rollBackPatch, rolledBackResult, type PatchRun } from "./failure.js";
import type { ValidationResult } from "./helpers.js";
import type { ApplyPatchFileInput } from "./input-schema.js";
import type { StepOutcome } from "./types.js";

/** Whether proof-of-fix applies to this run, and the reproduction script it would use. */
export interface ProofOfFixSettings {
  reproductionTestPath: string | undefined;
  active: boolean;
  requireProofOfFix: boolean | undefined;
}

type ProofStage = "negative" | "positive";

const MISSING_SCRIPT_MESSAGE =
  "Proof-of-fix verification required, but no reproduction test or script was supplied.";

export async function prepareProofOfFix(
  input: ApplyPatchFileInput,
  patchesDirPath: string,
): Promise<ProofOfFixSettings> {
  const preparedRepro = await prepareReproductionTestFile({
    cwd: input.cwd,
    packageName: input.packageName,
    vulnerableVersion: input.vulnerableVersion,
    patchesDir: patchesDirPath,
    proofOfFix: input.proofOfFix,
    reproductionTest: input.reproductionTest,
  });
  const reproductionTestPath = preparedRepro.testFilePath;
  const hasReproductionScript = Boolean(reproductionTestPath);
  return {
    reproductionTestPath,
    active: Boolean(hasReproductionScript || input.proofOfFix || input.requireProofOfFix),
    requireProofOfFix: input.requireProofOfFix,
  };
}

/** Runs the reproduction test on unpatched code; it must reproduce the vulnerability. */
export async function runNegativeProofStep(
  run: PatchRun,
  settings: ProofOfFixSettings,
): Promise<StepOutcome<ProofOfFixPhaseResult | undefined>> {
  const { reproductionTestPath, active, requireProofOfFix } = settings;
  if (!active) return { ok: true, value: undefined };

  if (!reproductionTestPath) {
    if (!requireProofOfFix) return { ok: true, value: undefined };
    await rollBackPatch(run, false);
    return {
      ok: false,
      result: rolledBackResult(run, {
        unresolvedReason: "policy-blocked",
        message: MISSING_SCRIPT_MESSAGE,
        postinstallConfigured: false,
      }),
    };
  }

  const negative = await runProofOfFixPhase({
    stage: "negative",
    testFilePath: reproductionTestPath,
    cwd: run.cwd,
  });
  recordProofPhase(
    run.validationPhases,
    "negative",
    negative,
    "Reproduction test reproduced vulnerability on unpatched code.",
  );
  if (negative.passed) return { ok: true, value: negative };
  return proofFailure(run, settings, "negative", negative, false);
}

/** Runs the reproduction test on patched code; it must no longer reproduce the vulnerability. */
export async function runPositiveProofStep(
  run: PatchRun,
  settings: ProofOfFixSettings,
): Promise<StepOutcome<ProofOfFixPhaseResult | undefined>> {
  const { reproductionTestPath, active } = settings;
  if (!reproductionTestPath || !active) return { ok: true, value: undefined };

  const positive = await runProofOfFixPhase({
    stage: "positive",
    testFilePath: reproductionTestPath,
    cwd: run.cwd,
  });
  recordProofPhase(
    run.validationPhases,
    "positive",
    positive,
    "Reproduction test passed on patched code (vulnerability mitigated).",
  );
  if (positive.passed) return { ok: true, value: positive };
  return proofFailure(run, settings, "positive", positive, run.patchMode === "patch-package");
}

export function buildProofOfFixVerification(params: {
  settings: ProofOfFixSettings;
  negative: ProofOfFixPhaseResult | undefined;
  positive: ProofOfFixPhaseResult | undefined;
  validation: ValidationResult | undefined;
}): ProofOfFixVerification | undefined {
  const { settings, negative, positive, validation } = params;
  if (!negative || !positive) return undefined;
  return assembleProofOfFixVerification({
    reproductionTestPath: settings.reproductionTestPath,
    negativePhase: negative,
    positivePhase: positive,
    regressionPhase: validation
      ? {
          executed: true,
          passed: validation.passed,
          error: validation.error,
        }
      : undefined,
  });
}

function recordProofPhase(
  phases: PatchValidationPhase[],
  stage: ProofStage,
  result: ProofOfFixPhaseResult,
  successMessage: string,
): void {
  phases.push({
    phase: stage === "negative" ? "proof-of-fix-negative" : "proof-of-fix-positive",
    passed: result.passed,
    message: result.passed ? successMessage : undefined,
    error: result.passed ? undefined : result.error,
  });
}

async function proofFailure(
  run: PatchRun,
  settings: ProofOfFixSettings,
  stage: ProofStage,
  result: ProofOfFixPhaseResult,
  rerunInstall: boolean,
): Promise<StepOutcome<never>> {
  await rollBackPatch(run, rerunInstall);
  const unresolvedReason: UnresolvedReason = settings.requireProofOfFix
    ? "policy-blocked"
    : "proof-of-fix-failed";
  return {
    ok: false,
    result: rolledBackResult(run, {
      unresolvedReason,
      message: `Proof-of-fix ${stage} phase failed: ${result.error}`,
      postinstallConfigured: false,
    }),
  };
}
