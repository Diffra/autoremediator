/**
 * Proof-of-fix half of apply-version-bump: the exploit reproduction must fail before the
 * upgrade (negative phase) and pass after it (positive phase).
 */
import { rm } from "node:fs/promises";

import type { PatchResult } from "../remediate/types.js";
import {
  assembleProofOfFixVerification,
  prepareReproductionTestFile,
  runProofOfFixPhase,
} from "../verify/proof-of-fix/runner.js";
import type { ProofOfFixPhaseResult, ProofOfFixVerification } from "../verify/types.js";
import type { VersionBumpInput } from "./version-bump-input.js";

/** What the negative phase learned; absent fields mean no reproduction test is in play. */
export interface ProofOfFixState {
  reproTestPath?: string;
  isCreated: boolean;
  negativePhaseResult?: ProofOfFixPhaseResult;
}

export type NegativePhaseOutcome =
  | { kind: "result"; result: PatchResult }
  | { kind: "state"; state: ProofOfFixState };

/** Prepares the reproduction test and runs it against the vulnerable version. */
export async function runNegativeProofPhase(
  input: VersionBumpInput,
): Promise<NegativePhaseOutcome> {
  const { cwd, packageName, fromVersion, toVersion, dryRun, requireProofOfFix } = input;
  const prepared = await prepareReproductionTestFile({
    cwd,
    packageName,
    vulnerableVersion: fromVersion,
    patchesDir: input.patchesDir,
    proofOfFix: input.proofOfFix,
    reproductionTest: input.reproductionTest,
  });
  const reproTestPath = prepared.testFilePath;
  const isProofActive = Boolean(reproTestPath || input.proofOfFix || requireProofOfFix);
  const state: ProofOfFixState = { reproTestPath, isCreated: prepared.isCreated };

  if (!isProofActive) {
    return { kind: "state", state };
  }

  if (!reproTestPath) {
    if (requireProofOfFix) {
      return {
        kind: "result",
        result: {
          packageName,
          strategy: "none",
          fromVersion,
          toVersion,
          applied: false,
          dryRun,
          unresolvedReason: "policy-blocked",
          message:
            "Proof-of-fix verification required, but no reproduction test or script was supplied.",
        },
      };
    }
    return { kind: "state", state };
  }

  const negativePhaseResult = await runProofOfFixPhase({
    stage: "negative",
    testFilePath: reproTestPath,
    cwd,
  });

  if (!negativePhaseResult.passed) {
    if (prepared.isCreated && reproTestPath) {
      await rm(reproTestPath, { force: true }).catch(() => {});
    }
    return {
      kind: "result",
      result: {
        packageName,
        strategy: "version-bump",
        fromVersion,
        toVersion,
        applied: false,
        dryRun: false,
        unresolvedReason: requireProofOfFix ? "policy-blocked" : "proof-of-fix-failed",
        message: `Proof-of-fix negative phase failed: ${negativePhaseResult.error}`,
      },
    };
  }

  return { kind: "state", state: { ...state, negativePhaseResult } };
}

export type PositivePhaseOutcome =
  | { kind: "result"; result: PatchResult }
  | { kind: "verified"; verification: ProofOfFixVerification | undefined };

/**
 * Runs the reproduction against the upgraded tree. On failure `rollback` restores the manifest
 * before the reproduction file is removed and the failure is reported.
 */
export async function runPositiveProofPhase(params: {
  input: VersionBumpInput;
  state: ProofOfFixState;
  validationPassed: boolean;
  rollback: () => Promise<void>;
}): Promise<PositivePhaseOutcome> {
  const { input, state, validationPassed, rollback } = params;
  const { reproTestPath, negativePhaseResult } = state;
  if (!reproTestPath || !negativePhaseResult?.passed) {
    return { kind: "verified", verification: undefined };
  }

  const positivePhaseResult = await runProofOfFixPhase({
    stage: "positive",
    testFilePath: reproTestPath,
    cwd: input.cwd,
  });

  if (!positivePhaseResult.passed) {
    await rollback();

    if (state.isCreated && reproTestPath) {
      await rm(reproTestPath, { force: true }).catch(() => {});
    }

    return {
      kind: "result",
      result: {
        packageName: input.packageName,
        strategy: "version-bump",
        fromVersion: input.fromVersion,
        toVersion: input.toVersion,
        applied: false,
        dryRun: false,
        unresolvedReason: input.requireProofOfFix ? "policy-blocked" : "proof-of-fix-failed",
        message: `Proof-of-fix positive phase failed: ${positivePhaseResult.error}`,
      },
    };
  }

  const verification = assembleProofOfFixVerification({
    reproductionTestPath: reproTestPath,
    negativePhase: negativePhaseResult,
    positivePhase: positivePhaseResult,
    regressionPhase: {
      executed: input.runTests,
      passed: validationPassed,
    },
  });
  return { kind: "verified", verification };
}
