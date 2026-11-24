/**
 * Everything apply-patch-file decides before it touches disk: package manager, policy, install and
 * test commands, the patch to apply, and its diff validation. Failures here return a result and
 * leave nothing to roll back.
 */
import { join } from "node:path";

import {
  detectPackageManager,
  getYarnMajorVersion,
  resolveInstallCommand,
  type PackageManager,
} from "../../../infra/package-manager/index.js";
import { isPackageAllowed, loadPolicy } from "../../../infra/policy/policy.js";
import type { UnresolvedReason } from "../../../shared/types.js";
import { resolveProjectTestCommand } from "../../memory/test-command.js";
import type { PatchValidationPhase } from "../../verify/types.js";
import { validatePatchDiff } from "../patch-utils.js";
import type { PatchArtifact } from "../types.js";
import {
  buildPatchFileName,
  computePatchIntegrity,
  countPatchHunks,
  extractPatchedFiles,
} from "./helpers.js";
import type { ApplyPatchFileInput } from "./input-schema.js";
import type { StepOutcome } from "./types.js";

/** What the run needs once the input has been checked. */
export interface PatchPlan {
  pm: PackageManager;
  installCommand: string[];
  testCommand: ReturnType<typeof resolveProjectTestCommand>;
  selectedPatch: string;
  patchesDir: string;
  patchFilePath: string;
  manifestFilePath: string;
  baseArtifact: PatchArtifact;
  validationPhases: PatchValidationPhase[];
}

export async function preparePatchPlan(
  input: ApplyPatchFileInput,
): Promise<StepOutcome<PatchPlan>> {
  const { packageName, cwd } = input;
  const pm = input.packageManager ?? detectPackageManager(cwd);
  const loadedPolicy = loadPolicy(cwd, input.policy);
  if (!isPackageAllowed(loadedPolicy, packageName)) {
    return rejected(input, {
      message: `Policy denyPackages blocked changes for package "${packageName}".`,
      unresolvedReason: "policy-blocked",
    });
  }
  const commandConstraints = {
    ...loadedPolicy.constraints,
    installMode: input.installMode ?? loadedPolicy.constraints?.installMode,
    installPreferOffline:
      input.installPreferOffline ?? loadedPolicy.constraints?.installPreferOffline,
    enforceFrozenLockfile:
      input.enforceFrozenLockfile ?? loadedPolicy.constraints?.enforceFrozenLockfile,
    workspace: input.workspace ?? loadedPolicy.constraints?.workspace,
  };
  const yarnMajor = pm === "yarn" ? await getYarnMajorVersion(cwd) : undefined;
  const installCommand = resolveInstallCommand(pm, commandConstraints, yarnMajor);
  const testCommand = resolveProjectTestCommand(pm, commandConstraints, cwd);
  const selectedPatch = input.patchContent ?? input.patches?.[0]?.unifiedDiff;
  const validationPhases: PatchValidationPhase[] = [];

  if (!selectedPatch) return rejected(input, { message: "No patch content provided." });

  const patchValidation = validatePatchDiff(selectedPatch);
  validationPhases.push({
    phase: "diff-format",
    passed: patchValidation.valid,
    error: patchValidation.valid ? undefined : patchValidation.error,
    message: patchValidation.valid ? "Patch content is a valid unified diff." : undefined,
  });

  if (!patchValidation.valid) {
    return rejected(input, {
      message: patchValidation.error ?? "Patch content is not a valid unified diff.",
      validationPhases,
    });
  }

  const patchFilePath = join(
    cwd,
    input.patchesDir,
    buildPatchFileName(packageName, input.vulnerableVersion),
  );
  const manifestFilePath = `${patchFilePath}.json`;
  return {
    ok: true,
    value: {
      pm,
      installCommand,
      testCommand,
      selectedPatch,
      patchesDir: input.patchesDir,
      patchFilePath,
      manifestFilePath,
      baseArtifact: buildBaseArtifact({
        input,
        selectedPatch,
        patchFilePath,
        manifestFilePath,
        validationPhases,
      }),
      validationPhases,
    },
  };
}

function rejected(
  input: ApplyPatchFileInput,
  rejection: {
    message: string;
    unresolvedReason?: UnresolvedReason;
    validationPhases?: PatchValidationPhase[];
  },
): StepOutcome<never> {
  return {
    ok: false,
    result: {
      success: false,
      packageName: input.packageName,
      vulnerableVersion: input.vulnerableVersion,
      applied: false,
      dryRun: input.dryRun,
      ...(rejection.unresolvedReason === undefined
        ? {}
        : { unresolvedReason: rejection.unresolvedReason }),
      message: rejection.message,
      ...(rejection.validationPhases === undefined
        ? {}
        : { validationPhases: rejection.validationPhases }),
      error: rejection.message,
    },
  };
}

function buildBaseArtifact(params: {
  input: ApplyPatchFileInput;
  selectedPatch: string;
  patchFilePath: string;
  manifestFilePath: string;
  validationPhases: PatchValidationPhase[];
}): PatchArtifact {
  const { input, selectedPatch, patchFilePath, manifestFilePath, validationPhases } = params;
  return {
    schemaVersion: "1.0",
    cveId: input.cveId,
    packageName: input.packageName,
    vulnerableVersion: input.vulnerableVersion,
    patchFilePath,
    manifestFilePath,
    patchFileName: buildPatchFileName(input.packageName, input.vulnerableVersion),
    patchesDir: input.patchesDir,
    confidence: input.confidence,
    riskLevel: input.riskLevel,
    generatedAt: new Date().toISOString(),
    files: extractPatchedFiles(selectedPatch),
    hunkCount: countPatchHunks(selectedPatch),
    applied: false,
    dryRun: input.dryRun,
    integrity: computePatchIntegrity(selectedPatch),
    validationPhases,
  };
}
