import { existsSync } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  detectPackageManager,
  resolveInstallCommand,
} from "../../../infra/package-manager/index.js";
import { errorMessage } from "../../../shared/errors.js";
import { safeExecaCommand } from "../../../shared/exec/safe-exec-command.js";
import { LONG_RUNNING_TIMEOUT_MS } from "../../../shared/timeouts.js";
import { assertAutonomyAllows } from "../../autonomy/index.js";
import { evaluatePackage } from "../../intelligence/evaluate-package.js";
import { resolveProjectTestCommand } from "../../memory/test-command.js";
import {
  getOverrideValue,
  setOverrideValue,
  type RawPackageJson,
} from "../../upgrade/apply-package-override/helpers.js";
import type {
  PatchReconcileOptions,
  PatchReconcileReport,
  PatchReconcileResult,
} from "../types.js";
import { inspectPatchArtifact, listPatchArtifacts } from "./inspection.js";

/**
 * Reconciles active patch artifacts in patchesDir against upstream registries.
 * If safe upstream releases have been published, the patches can be retired and packages upgraded.
 */
export async function reconcilePatchArtifacts(
  options: PatchReconcileOptions = {},
): Promise<PatchReconcileReport> {
  const cwd = options.cwd ?? process.cwd();
  if (options.autoApply) {
    assertAutonomyAllows(cwd, undefined, "apply", "reconcilePatchArtifacts autoApply");
  }
  const pm = options.packageManager ?? detectPackageManager(cwd);

  const summaries = await listPatchArtifacts(options);
  const results: PatchReconcileResult[] = [];
  for (const summary of summaries) {
    results.push(await reconcileOne(summary, options, { cwd, pm }));
  }

  const reconciledCount = results.filter((r) => r.status === "upgraded").length;
  const retainedCount = results.filter(
    (r) => r.status === "patch-retained" || r.status === "safe-version-available",
  ).length;

  return {
    reconciled: results,
    reconciledCount,
    retainedCount,
  };
}

type PatchSummary = Awaited<ReturnType<typeof listPatchArtifacts>>[number];
type PatchInspection = Awaited<ReturnType<typeof inspectPatchArtifact>>;

interface ReconcileEnvironment {
  cwd: string;
  pm: ReturnType<typeof detectPackageManager>;
}

async function reconcileOne(
  summary: PatchSummary,
  options: PatchReconcileOptions,
  env: ReconcileEnvironment,
): Promise<PatchReconcileResult> {
  const inspection = await inspectPatchArtifact(summary.patchFilePath, options);
  const { packageName, vulnerableVersion } = patchSubject(summary, inspection);
  const cveId = inspection.cveId;

  if (!packageName) {
    return {
      patchFilePath: summary.patchFilePath,
      packageName: "unknown",
      cveId,
      status: "patch-retained",
      reason: "Cannot determine package name from patch artifact.",
    };
  }

  const base = {
    patchFilePath: summary.patchFilePath,
    packageName,
    cveId,
    installedVersion: vulnerableVersion,
  };
  const safeUpgradeVersion = await findSafeUpgrade(packageName, vulnerableVersion, cveId);

  if (!safeUpgradeVersion) {
    return {
      ...base,
      status: "patch-retained",
      reason: "No safe upstream release exists yet; patch remains necessary.",
    };
  }
  if (!options.autoApply) {
    return {
      ...base,
      safeUpstreamVersion: safeUpgradeVersion,
      status: "safe-version-available",
      reason: `Safe upstream version ${safeUpgradeVersion} is available. Re-run with autoApply: true or --auto-apply to upgrade.`,
    };
  }
  return applySafeUpgrade(
    { ...base, safeUpstreamVersion: safeUpgradeVersion },
    { summary, inspection, options, env },
  );
}

/** The package and vulnerable version a patch is for: its manifest, else its file name. */
function patchSubject(
  summary: PatchSummary,
  inspection: PatchInspection,
): { packageName: string | undefined; vulnerableVersion: string | undefined } {
  let packageName = inspection.packageName;
  let vulnerableVersion = inspection.vulnerableVersion;
  if (!packageName && summary.patchFileName) {
    const basename = summary.patchFileName.replace(/\.patch$/, "");
    const plusIdx = basename.lastIndexOf("+");
    if (plusIdx > 0) {
      let rawPkg = basename.slice(0, plusIdx);
      vulnerableVersion = basename.slice(plusIdx + 1);
      if (rawPkg.includes("+")) {
        rawPkg = "@" + rawPkg.replace("+", "/");
      }
      packageName = rawPkg;
    } else {
      packageName = basename;
    }
  }
  return { packageName, vulnerableVersion };
}

/** The version that fixes the advisory (or any advisory), or undefined when none is known. */
async function findSafeUpgrade(
  packageName: string,
  vulnerableVersion: string | undefined,
  cveId: string | undefined,
): Promise<string | undefined> {
  try {
    const evaluation = await evaluatePackage(packageName, {
      version: vulnerableVersion,
      enrichIntelligence: false,
    });
    if (cveId) {
      const vuln = evaluation.vulnerabilities.find(
        (v) => v.cveId.toLowerCase() === cveId.toLowerCase(),
      );
      return vuln?.safeUpgradeVersion || undefined;
    }
    return evaluation.vulnerabilities.find((v) => v.safeUpgradeVersion)?.safeUpgradeVersion;
  } catch {
    // Evaluation query failed or offline; the patch is kept as the unresolved result says.
    return undefined;
  }
}

interface Originals {
  pkgJsonPath: string;
  pkgJson: string | undefined;
  patchPath: string;
  patch: string | undefined;
  manifestPath: string;
  manifest: string | undefined;
}

async function readIfPresent(path: string): Promise<string | undefined> {
  return existsSync(path) ? readFile(path, "utf8") : undefined;
}

/** What the files held before the upgrade, so a failed install or test can put it back. */
async function readOriginals(
  cwd: string,
  patchPath: string,
  manifestPath: string,
): Promise<Originals> {
  const pkgJsonPath = join(cwd, "package.json");
  return {
    pkgJsonPath,
    pkgJson: await readIfPresent(pkgJsonPath),
    patchPath,
    patch: await readIfPresent(patchPath),
    manifestPath,
    manifest: await readIfPresent(manifestPath),
  };
}

async function restoreOriginals(originals: Originals): Promise<void> {
  if (originals.pkgJson) await writeFile(originals.pkgJsonPath, originals.pkgJson, "utf8");
  if (originals.patch) await writeFile(originals.patchPath, originals.patch, "utf8");
  if (originals.manifest) await writeFile(originals.manifestPath, originals.manifest, "utf8");
}

/** Points the package at the safe version in package.json; returns whether anything changed. */
function upgradeManifest(
  pkgJsonText: string,
  pm: ReconcileEnvironment["pm"],
  packageName: string,
  safeVersion: string,
): { text: string; updated: boolean } {
  const pkgJson = JSON.parse(pkgJsonText) as RawPackageJson &
    Record<string, Record<string, string> | undefined>;
  let updated = false;

  const depSections = [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
  ];
  let foundInDirectDeps = false;
  for (const depSection of depSections) {
    if (pkgJson[depSection]?.[packageName]) {
      pkgJson[depSection][packageName] = `^${safeVersion}`;
      updated = true;
      foundInDirectDeps = true;
    }
  }

  // Handle existing or newly needed transitive overrides
  const existingOverride = getOverrideValue(pkgJson, pm, packageName);
  if (existingOverride || !foundInDirectDeps) {
    setOverrideValue(pkgJson, pm, packageName, safeVersion);
    updated = true;
  }

  // Remove from pnpm patchedDependencies if present
  if (pkgJson.pnpm?.patchedDependencies) {
    const patched = pkgJson.pnpm.patchedDependencies as Record<string, string>;
    for (const key of Object.keys(patched)) {
      if (key.startsWith(`${packageName}@`)) {
        delete patched[key];
        updated = true;
      }
    }
  }
  return { text: JSON.stringify(pkgJson, null, 2) + "\n", updated };
}

/** Upgrades the package, retires the patch artifact and verifies; any failure restores the files. */
async function applySafeUpgrade(
  base: Omit<PatchReconcileResult, "status" | "reason"> & { safeUpstreamVersion: string },
  context: {
    summary: PatchSummary;
    inspection: PatchInspection;
    options: PatchReconcileOptions;
    env: ReconcileEnvironment;
  },
): Promise<PatchReconcileResult> {
  const { summary, inspection, options, env } = context;
  const { cwd, pm } = env;
  const manifestPath = inspection.manifestFilePath ?? `${summary.patchFilePath}.json`;
  const fail = (reason: string): PatchReconcileResult => ({ ...base, status: "error", reason });

  try {
    // Snapshot pre-mutation state for truthful rollback on command failure
    const originals = await readOriginals(cwd, summary.patchFilePath, manifestPath);

    if (originals.pkgJson) {
      const upgraded = upgradeManifest(
        originals.pkgJson,
        pm,
        base.packageName,
        base.safeUpstreamVersion,
      );
      if (upgraded.updated) await writeFile(originals.pkgJsonPath, upgraded.text, "utf8");
    }

    // Remove patch artifacts
    await rm(summary.patchFilePath, { force: true });
    if (existsSync(manifestPath)) {
      await rm(manifestPath, { force: true });
    }

    // Execute package installation truthfully
    const installCmd = resolveInstallCommand(pm);
    try {
      await safeExecaCommand(installCmd, {
        timeoutMs: LONG_RUNNING_TIMEOUT_MS,
        cwd,
        stdio: "pipe",
      });
    } catch (installErr) {
      await restoreOriginals(originals);
      return fail(
        `Package manager installation failed (${installCmd.join(" ")}): ${errorMessage(installErr)}. Restored original package.json and patch artifacts.`,
      );
    }

    // Execute tests truthfully if requested
    if (options.runTests) {
      const testCmd = resolveProjectTestCommand(pm, undefined, cwd);
      try {
        await safeExecaCommand(testCmd, { timeoutMs: LONG_RUNNING_TIMEOUT_MS, cwd, stdio: "pipe" });
      } catch (testErr) {
        await restoreOriginals(originals);
        return fail(
          `Validation tests failed post-upgrade (${testCmd.join(" ")}): ${errorMessage(testErr)}. Restored original package.json and patch artifacts.`,
        );
      }
    }

    return {
      ...base,
      status: "upgraded",
      reason: `Successfully upgraded to ${base.safeUpstreamVersion} and retired patch artifact.`,
    };
  } catch (err) {
    return fail(errorMessage(err));
  }
}
