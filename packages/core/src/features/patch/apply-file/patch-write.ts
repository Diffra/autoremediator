/**
 * Writes the patch file and its manifest into the patches directory, recording both for rollback.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { recordFileTouch } from "../../../infra/rollback/rollback.js";
import type { PatchMode } from "../../../shared/types.js";
import type { PatchArtifact } from "../types.js";
import {
  capturePackageJsonSnapshot,
  patchModeRequiresPackageJsonSnapshot,
  resolvePatchMode,
  writePatchManifest,
  type PackageJsonSnapshot,
} from "./helpers.js";
import type { PatchPlan } from "./preflight.js";

export interface WrittenPatch {
  packageJsonSnapshot: PackageJsonSnapshot | undefined;
  patchMode: PatchMode;
  artifact: PatchArtifact;
  patchesDirPath: string;
}

export async function writePatchFiles(plan: PatchPlan, cwd: string): Promise<WrittenPatch> {
  const { pm, selectedPatch, baseArtifact, patchFilePath, manifestFilePath, validationPhases } =
    plan;
  const packageJsonSnapshot = patchModeRequiresPackageJsonSnapshot(pm)
    ? await capturePackageJsonSnapshot(cwd)
    : undefined;

  const patchesDirPath = join(cwd, plan.patchesDir);
  await mkdir(patchesDirPath, { recursive: true });

  recordFileTouch(patchFilePath);
  recordFileTouch(manifestFilePath);
  await writeFile(patchFilePath, selectedPatch, "utf8");
  validationPhases.push({
    phase: "patch-write",
    passed: true,
    message: `Patch file written to ${patchFilePath}.`,
  });

  const patchMode = await resolvePatchMode(pm, cwd);
  const artifact: PatchArtifact = {
    ...baseArtifact,
    patchMode,
    validationPhases,
  };

  await writePatchManifest(manifestFilePath, artifact);
  validationPhases.push({
    phase: "manifest-write",
    passed: true,
    message: `Patch manifest written to ${manifestFilePath}.`,
  });
  artifact.validationPhases = validationPhases;
  await writePatchManifest(manifestFilePath, artifact);

  return { packageJsonSnapshot, patchMode, artifact, patchesDirPath };
}
