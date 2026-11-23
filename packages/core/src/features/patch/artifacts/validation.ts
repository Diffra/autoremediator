import { detectPackageManager } from "../../../infra/package-manager/index.js";
import { checkInventoryTool } from "../../remediate/tools/check-inventory.js";
import type { PatchValidationPhase } from "../../verify/types.js";
import type { PatchArtifactQueryOptions, PatchArtifactValidationReport } from "../types.js";
import { inspectPatchArtifact } from "./inspection.js";

export async function validatePatchArtifact(
  patchFilePath: string,
  options: PatchArtifactQueryOptions = {},
): Promise<PatchArtifactValidationReport> {
  const inspection = await inspectPatchArtifact(patchFilePath, options);
  const validationPhases: PatchValidationPhase[] = [
    {
      phase: "diff-format",
      passed: inspection.diffValid,
      error: inspection.diffValid ? undefined : inspection.formatError,
      message: inspection.diffValid ? "Patch content is a valid unified diff." : undefined,
    },
  ];

  if (!inspection.exists) {
    return {
      patchFilePath: inspection.patchFilePath,
      manifestFilePath: inspection.manifestFilePath,
      exists: false,
      manifestFound: false,
      diffValid: false,
      formatError: inspection.formatError,
      driftDetected: false,
      validationPhases,
    };
  }

  const manifest = inspection.manifest;
  const manifestFound = Boolean(manifest);

  if (!manifest) {
    validationPhases.push({
      phase: "manifest-write",
      passed: false,
      error: "No patch manifest found for this patch artifact.",
    });

    return {
      patchFilePath: inspection.patchFilePath,
      manifestFilePath: inspection.manifestFilePath,
      exists: true,
      manifestFound,
      diffValid: inspection.diffValid,
      formatError: inspection.formatError,
      driftDetected: false,
      validationPhases,
    };
  }

  validationPhases.push({
    phase: "manifest-write",
    passed: true,
    message: "Patch manifest is present.",
  });

  const cwd = options.cwd ?? process.cwd();
  const packageManager = options.packageManager ?? detectPackageManager(cwd);
  const inventory = await checkInventoryTool.execute({ cwd, packageManager });

  if (inventory.error) {
    validationPhases.push({
      phase: "drift",
      passed: false,
      error: inventory.error,
    });

    return {
      patchFilePath: inspection.patchFilePath,
      manifestFilePath: inspection.manifestFilePath,
      exists: true,
      manifestFound,
      diffValid: inspection.diffValid,
      formatError: inspection.formatError,
      driftDetected: false,
      cveId: manifest.cveId,
      packageName: manifest.packageName,
      vulnerableVersion: manifest.vulnerableVersion,
      validationPhases,
    };
  }

  const matchingPackages = (inventory.packages ?? []).filter(
    (pkg) => pkg.name === manifest.packageName,
  );
  const installedVersion = matchingPackages[0]?.version;
  const inventoryMatch = matchingPackages.some((pkg) => pkg.version === manifest.vulnerableVersion);
  const driftDetected = matchingPackages.length > 0 && !inventoryMatch;

  validationPhases.push({
    phase: "drift",
    passed: !driftDetected,
    message: driftMessage(manifest, matchingPackages.length, inventoryMatch, installedVersion),
    error: driftDetected
      ? "Patch manifest does not match the installed dependency version."
      : undefined,
  });

  return {
    patchFilePath: inspection.patchFilePath,
    manifestFilePath: inspection.manifestFilePath,
    exists: true,
    manifestFound,
    diffValid: inspection.diffValid,
    formatError: inspection.formatError,
    driftDetected,
    cveId: manifest.cveId,
    packageName: manifest.packageName,
    vulnerableVersion: manifest.vulnerableVersion,
    installedVersion,
    inventoryMatch,
    validationPhases,
  };
}

function driftMessage(
  target: { packageName: string; vulnerableVersion: string },
  matchingCount: number,
  inventoryMatch: boolean,
  installedVersion: string | undefined,
): string {
  if (matchingCount === 0) {
    return `Package ${target.packageName} is not currently installed.`;
  }
  if (inventoryMatch) {
    return `Installed version matches manifest target ${target.vulnerableVersion}.`;
  }
  return `Installed version ${installedVersion} does not match manifest target ${target.vulnerableVersion}.`;
}
