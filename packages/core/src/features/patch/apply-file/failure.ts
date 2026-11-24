/**
 * What the locked part of apply-patch-file shares: the run being applied, how a failed step rolls
 * it back, and the result shape every rolled-back failure returns.
 */
import type { PatchMode, UnresolvedReason } from "../../../shared/types.js";
import type { PatchValidationPhase } from "../../verify/types.js";
import type { PatchArtifact } from "../types.js";
import {
  cleanupPatchArtifacts,
  type PackageJsonSnapshot,
  type ValidationResult,
} from "./helpers.js";
import type { ApplyPatchFileResult } from "./types.js";

/** The patch being applied, once its files are on disk. */
export interface PatchRun {
  cwd: string;
  packageName: string;
  vulnerableVersion: string;
  patchFilePath: string;
  manifestFilePath: string;
  patchMode: PatchMode;
  installCommand: string[];
  packageJsonSnapshot: PackageJsonSnapshot | undefined;
  artifact: PatchArtifact;
  validationPhases: PatchValidationPhase[];
}

export interface RolledBackFailure {
  message: string;
  postinstallConfigured: boolean | undefined;
  unresolvedReason?: UnresolvedReason;
  validation?: ValidationResult;
}

export async function rollBackPatch(run: PatchRun, rerunInstall: boolean): Promise<void> {
  await cleanupPatchArtifacts({
    cwd: run.cwd,
    patchFilePath: run.patchFilePath,
    manifestFilePath: run.manifestFilePath,
    patchMode: run.patchMode,
    packageJsonSnapshot: run.packageJsonSnapshot,
    installCommand: run.installCommand,
    rerunInstall,
  });
}

export function rolledBackResult(run: PatchRun, failure: RolledBackFailure): ApplyPatchFileResult {
  return {
    success: false,
    packageName: run.packageName,
    vulnerableVersion: run.vulnerableVersion,
    applied: false,
    dryRun: false,
    ...(failure.unresolvedReason === undefined
      ? {}
      : { unresolvedReason: failure.unresolvedReason }),
    message: failure.message,
    patchFilePath: run.patchFilePath,
    manifestFilePath: run.manifestFilePath,
    patchPath: run.patchFilePath,
    patchMode: run.patchMode,
    postinstallConfigured: failure.postinstallConfigured,
    patchArtifact: {
      ...run.artifact,
      applied: false,
      validationPhases: run.validationPhases,
    },
    ...(failure.validation === undefined ? {} : { validation: failure.validation }),
    validationPhases: run.validationPhases,
    error: failure.message,
  };
}
