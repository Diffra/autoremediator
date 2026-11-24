/**
 * The steps that change the project in apply-patch-file: apply the patch, reinstall for
 * patch-package, and run the project's tests. Each rolls the patch back when it fails.
 */
import { errorMessage } from "../../../shared/errors.js";
import { safeExecaCommand } from "../../../shared/exec/safe-exec-command.js";
import { LONG_RUNNING_TIMEOUT_MS } from "../../../shared/timeouts.js";
import type { PackageManager } from "../../../shared/types.js";
import { rollBackPatch, rolledBackResult, type PatchRun } from "./failure.js";
import {
  applyNativePatch,
  configurePatchPackagePostinstall,
  validatePatchWithTests,
  type ValidationResult,
} from "./helpers.js";
import type { StepOutcome } from "./types.js";

export async function applyPatchToProject(params: {
  run: PatchRun;
  pm: PackageManager;
  patchContent: string;
}): Promise<StepOutcome<undefined>> {
  const { run, pm, patchContent } = params;
  const { cwd, patchMode, packageName, vulnerableVersion, validationPhases } = run;
  const applyResult =
    patchMode === "patch-package"
      ? await configurePatchPackagePostinstall(cwd, pm)
      : await applyNativePatch({
          cwd,
          packageName,
          vulnerableVersion,
          patchContent,
          patchMode,
          validationPhases,
        });

  if (!applyResult.success) {
    await rollBackPatch(run, patchMode === "patch-package");
    return {
      ok: false,
      result: rolledBackResult(run, {
        message: applyResult.error,
        postinstallConfigured: patchMode === "patch-package" ? false : undefined,
      }),
    };
  }

  validationPhases.push({
    phase: "apply",
    passed: true,
    message: `Patch applied using ${patchMode}.`,
  });
  return { ok: true, value: undefined };
}

/** patch-package patches are applied by the install's postinstall hook, so it must be re-run. */
export async function runPatchPackageInstall(run: PatchRun): Promise<StepOutcome<undefined>> {
  if (run.patchMode !== "patch-package") return { ok: true, value: undefined };
  const { cwd, installCommand, validationPhases } = run;
  try {
    await safeExecaCommand(installCommand, {
      timeoutMs: LONG_RUNNING_TIMEOUT_MS,
      cwd,
      stdio: "pipe",
    });
    validationPhases.push({
      phase: "install",
      passed: true,
      message: `${installCommand.join(" ")} completed successfully.`,
    });
    return { ok: true, value: undefined };
  } catch (err) {
    await rollBackPatch(run, true);
    const error = errorMessage(err);
    validationPhases.push({
      phase: "install",
      passed: false,
      error,
    });
    return {
      ok: false,
      result: rolledBackResult(run, {
        message: `Failed to apply patch-package workflow for ${run.packageName}@${run.vulnerableVersion}: ${error}`,
        postinstallConfigured: false,
      }),
    };
  }
}

export async function runPatchValidationTests(
  run: PatchRun,
  testCommand: Parameters<typeof validatePatchWithTests>[1],
): Promise<StepOutcome<ValidationResult>> {
  const validationResult = await validatePatchWithTests(run.cwd, testCommand);
  if (!validationResult.passed) {
    await rollBackPatch(run, run.patchMode === "patch-package");
    run.validationPhases.push({
      phase: "test",
      passed: false,
      error: validationResult.error,
    });
    return {
      ok: false,
      result: rolledBackResult(run, {
        message: "Patch validation failed after apply; patch marked unresolved.",
        postinstallConfigured: false,
        validation: validationResult,
      }),
    };
  }

  run.validationPhases.push({
    phase: "test",
    passed: true,
    message: "Patch validation tests passed.",
  });
  return { ok: true, value: validationResult };
}
