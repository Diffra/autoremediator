/**
 * Result and step types shared by the apply-patch-file steps.
 */
import type { PatchMode, UnresolvedReason } from "../../../shared/types.js";
import type { PatchValidationPhase, ProofOfFixVerification } from "../../verify/types.js";
import type { PatchArtifact } from "../types.js";
import type { ValidationResult } from "./helpers.js";

export interface ApplyPatchFileResult {
  success: boolean;
  packageName: string;
  vulnerableVersion: string;
  applied: boolean;
  dryRun: boolean;
  message: string;
  patchFilePath?: string;
  manifestFilePath?: string;
  patchPath?: string;
  patchMode?: PatchMode;
  postinstallConfigured?: boolean;
  patchArtifact?: PatchArtifact;
  validation?: ValidationResult;
  validationPhases?: PatchValidationPhase[];
  proofOfFix?: ProofOfFixVerification;
  unresolvedReason?: UnresolvedReason;
  error?: string;
}

/** A step either hands its value on, or stops the run with the result to return. */
export type StepOutcome<T> = { ok: true; value: T } | { ok: false; result: ApplyPatchFileResult };
