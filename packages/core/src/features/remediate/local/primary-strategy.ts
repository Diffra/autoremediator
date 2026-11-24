import { loadRegistryConfig } from "../../../infra/http/registry-config.js";
import { readCooldown, withCooldown } from "../../../infra/package-manager/cooldown.js";
import type { RemediationConstraints } from "../../../infra/policy/types.js";
import type { PackageManager } from "../../../shared/types.js";
import type { VulnerablePackage } from "../../intelligence/types.js";
import { applyPackageOverrideTool } from "../../upgrade/apply-package-override/index.js";
import { applyVersionBumpTool } from "../../upgrade/apply-version-bump.js";
import type { PatchResult } from "../types.js";
import { describeSkipped, selectUpgradeTarget } from "./select-target.js";

/** Every fixed version was rejected in an earlier run: nothing to propose until a person says otherwise. */
function memoryBlocked(
  pkg: VulnerablePackage["installed"],
  target: { version: string; reason: string },
  dryRun: boolean,
  vulnerable: VulnerablePackage,
): PatchResult {
  return {
    packageName: pkg.name,
    strategy: "none",
    fromVersion: pkg.version,
    applied: false,
    dryRun,
    unresolvedReason: "constraint-blocked",
    vulnerableRange: vulnerable.affected.vulnerableRange,
    message: `Remediation memory blocks every fixed version of "${pkg.name}": ${target.reason}. Remove the entry with \`autoremediator memory remove\`, or pass --ignore-memory.`,
  };
}

interface PrimaryParams {
  vulnerable: VulnerablePackage;
  cwd: string;
  packageManager: PackageManager;
  dryRun: boolean;
  policy: string;
  runTests: boolean;
  constraints: RemediationConstraints;
  proofOfFix?: boolean | string;
  requireProofOfFix?: boolean;
  reproductionTest?: string;
  patchesDir?: string;
  /** Offline intelligence runs skip the advisory lookup on candidate versions. */
  offlineIntelligence?: boolean;
  /** Versions of this package remediation memory says were rejected, with why. */
  rejectedVersions?: ReadonlyMap<string, string>;
}

/** A result that says why nothing was applied. */
function unresolved(
  vulnerable: VulnerablePackage,
  dryRun: boolean,
  reason: NonNullable<PatchResult["unresolvedReason"]>,
  message: string,
  withRange = true,
): { result: PatchResult } {
  const pkg = vulnerable.installed;
  return {
    result: {
      packageName: pkg.name,
      strategy: "none",
      fromVersion: pkg.version,
      applied: false,
      dryRun,
      unresolvedReason: reason,
      ...(withRange ? { vulnerableRange: vulnerable.affected.vulnerableRange } : {}),
      message,
    },
  };
}

/** The constraints that rule out fixing a transitive dependency at all. */
function transitiveConstraintBlock(params: PrimaryParams): { result: PatchResult } | undefined {
  const { vulnerable, dryRun, constraints } = params;
  const name = vulnerable.installed.name;
  if (constraints.directDependenciesOnly) {
    return unresolved(
      vulnerable,
      dryRun,
      "constraint-blocked",
      `Constraint blocked remediation for transitive dependency "${name}".`,
      false,
    );
  }
  if (constraints.preferVersionBump) {
    return unresolved(
      vulnerable,
      dryRun,
      "constraint-blocked",
      `Constraint prefers version-bump and rejected override remediation for "${name}".`,
      false,
    );
  }
  return undefined;
}

type Target = Awaited<ReturnType<typeof selectUpgradeTarget>>;

/** The result for a target that cannot be applied. */
function targetBlock(
  params: PrimaryParams,
  target: Exclude<Target, { status: "selected" }>,
  kind: "override" | "upgrade",
): { result: PatchResult } {
  const { vulnerable, dryRun } = params;
  const pkg = vulnerable.installed;
  if (target.status === "memory-blocked") {
    return { result: memoryBlocked(pkg, target, dryRun, vulnerable) };
  }
  if (target.status === "no-safe-version") {
    return unresolved(
      vulnerable,
      dryRun,
      "no-safe-version",
      `No safe ${kind} version found for ${pkg.name}.`,
    );
  }
  return unresolved(
    vulnerable,
    dryRun,
    "policy-blocked",
    `Supply chain trust gate blocked "${pkg.name}@${target.version}": ${target.reason}`,
  );
}

function applyOverride(params: PrimaryParams, toVersion: string): Promise<PatchResult> {
  const { vulnerable, constraints } = params;
  return applyPackageOverrideTool.execute({
    cwd: params.cwd,
    packageManager: params.packageManager,
    packageName: vulnerable.installed.name,
    fromVersion: vulnerable.installed.version,
    toVersion,
    dryRun: params.dryRun,
    policy: params.policy,
    runTests: params.runTests,
    installMode: constraints.installMode,
    installPreferOffline: constraints.installPreferOffline,
    enforceFrozenLockfile: constraints.enforceFrozenLockfile,
    workspace: constraints.workspace,
    proofOfFix: params.proofOfFix,
    requireProofOfFix: params.requireProofOfFix ?? constraints.requireProofOfFix,
    reproductionTest: params.reproductionTest,
    patchesDir: params.patchesDir,
  });
}

function applyBump(params: PrimaryParams, toVersion: string): Promise<PatchResult> {
  const { vulnerable, constraints } = params;
  return applyVersionBumpTool.execute({
    cwd: params.cwd,
    packageManager: params.packageManager,
    packageName: vulnerable.installed.name,
    fromVersion: vulnerable.installed.version,
    toVersion,
    dryRun: params.dryRun,
    policy: params.policy,
    runTests: params.runTests,
    typecheck: constraints.typecheck,
    installMode: constraints.installMode,
    installPreferOffline: constraints.installPreferOffline,
    enforceFrozenLockfile: constraints.enforceFrozenLockfile,
    workspace: constraints.workspace,
    breakingChangeRefactor: constraints.enableBreakingChangeRefactor,
    proofOfFix: params.proofOfFix,
    requireProofOfFix: params.requireProofOfFix ?? constraints.requireProofOfFix,
    reproductionTest: params.reproductionTest,
    patchesDir: params.patchesDir,
  });
}

/**
 * Fixes one vulnerable package the deterministic way: a version bump for a direct dependency, an
 * override for a transitive one, once a safe, trusted target version has been chosen.
 */
export async function resolvePrimaryResult(
  params: PrimaryParams,
): Promise<{ result: PatchResult }> {
  const { vulnerable, cwd, packageManager, dryRun, constraints } = params;
  const pkg = vulnerable.installed;
  const transitive = pkg.type === "transitive";
  const kind = transitive ? "override" : "upgrade";

  if (transitive) {
    const blocked = transitiveConstraintBlock(params);
    if (blocked) return blocked;
  }
  const firstPatchedVersion = vulnerable.affected.firstPatchedVersion;
  if (!firstPatchedVersion) {
    return unresolved(
      vulnerable,
      dryRun,
      "no-safe-version",
      `No firstPatchedVersion available for ${pkg.name}; cannot resolve deterministic ${kind} in local mode.`,
    );
  }

  const target = await selectUpgradeTarget({
    packageName: pkg.name,
    installedVersion: pkg.version,
    firstPatchedVersion,
    vulnerableRange: vulnerable.affected.vulnerableRange,
    registry: loadRegistryConfig(cwd),
    supplyChainPolicy: withCooldown(
      constraints.supplyChainPolicy,
      readCooldown(cwd, packageManager),
      pkg.name,
    ),
    offline: params.offlineIntelligence,
    rejected: params.rejectedVersions,
  });
  if (target.status !== "selected") return targetBlock(params, target, kind);

  const applied = transitive
    ? await applyOverride(params, target.version)
    : await applyBump(params, target.version);
  return {
    result: {
      ...applied,
      vulnerableRange: vulnerable.affected.vulnerableRange,
      message: `${applied.message}${describeSkipped(target.skipped)}`,
    },
  };
}
