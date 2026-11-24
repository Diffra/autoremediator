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
    return reportOf(inspection, validationPhases, {
      exists: false,
      manifestFound: false,
      diffValid: false,
      driftDetected: false,
    });
  }

  const manifest = inspection.manifest;
  const manifestFound = Boolean(manifest);

  if (!manifest) {
    validationPhases.push({
      phase: "manifest-write",
      passed: false,
      error: "No patch manifest found for this patch artifact.",
    });

    return reportOf(inspection, validationPhases, {
      exists: true,
      manifestFound,
      driftDetected: false,
    });
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

    return reportOf(inspection, validationPhases, {
      exists: true,
      manifestFound,
      driftDetected: false,
      ...manifestFields(manifest),
    });
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

  return reportOf(inspection, validationPhases, {
    exists: true,
    manifestFound,
    driftDetected,
    ...manifestFields(manifest),
    installedVersion,
    inventoryMatch,
  });
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

type Inspection = Awaited<ReturnType<typeof inspectPatchArtifact>>;
type ReportFields = Pick<
  PatchArtifactValidationReport,
  "exists" | "manifestFound" | "driftDetected"
> &
  Partial<PatchArtifactValidationReport>;

/** The report fields every outcome shares, with what differs between outcomes in `fields`. */
function reportOf(
  inspection: Inspection,
  validationPhases: PatchValidationPhase[],
  fields: ReportFields,
): PatchArtifactValidationReport {
  return {
    patchFilePath: inspection.patchFilePath,
    manifestFilePath: inspection.manifestFilePath,
    diffValid: inspection.diffValid,
    formatError: inspection.formatError,
    validationPhases,
    ...fields,
  };
}

function manifestFields(manifest: NonNullable<Inspection["manifest"]>) {
  return {
    cveId: manifest.cveId,
    packageName: manifest.packageName,
    vulnerableVersion: manifest.vulnerableVersion,
  };
}
