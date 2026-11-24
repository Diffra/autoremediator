/**
 * Planning half of apply-version-bump: decide whether the bump may go ahead and what it would
 * change. Nothing here writes to disk; a refusal or a dry run comes back as a finished result.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import semver from "semver";

import {
  detectPackageManager,
  getYarnMajorVersion,
  resolveDedupeCommand,
  resolveInstallCommand,
  resolveTypecheckCommand,
} from "../../infra/package-manager/index.js";
import { findDeclaringWorkspacePackage } from "../../infra/package-manager/workspace.js";
import { isPackageAllowed, loadPolicy } from "../../infra/policy/policy.js";
import type { AutoremediatorPolicy } from "../../infra/policy/policy.js";
import { resolveProjectTestCommand } from "../memory/test-command.js";
import type { PatchResult } from "../remediate/types.js";
import type { VersionBumpInput } from "./version-bump-input.js";

export interface RawPackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  [key: string]: unknown;
}

type DepField = "dependencies" | "devDependencies" | "peerDependencies";

const DEP_FIELDS: DepField[] = ["dependencies", "devDependencies", "peerDependencies"];

export interface VersionBumpCommands {
  install: string[];
  test: string[];
  typecheck: string[];
  dedupe: string[];
}

export interface VersionBumpPlan {
  pkgPath: string;
  pkgJson: RawPackageJson;
  depField: DepField;
  currentRange: string;
  newRange: string;
  loadedPolicy: AutoremediatorPolicy;
  commands: VersionBumpCommands;
  shouldTypecheck: boolean;
}

export type VersionBumpPlanOutcome =
  | { kind: "result"; result: PatchResult }
  | { kind: "plan"; plan: VersionBumpPlan };

export async function planVersionBump(input: VersionBumpInput): Promise<VersionBumpPlanOutcome> {
  const { cwd, packageName, fromVersion, toVersion, dryRun, workspace } = input;
  const pm = input.packageManager ?? detectPackageManager(cwd);
  const loadedPolicy = loadPolicy(cwd, input.policy);
  const commandConstraints = {
    ...loadedPolicy.constraints,
    installMode: input.installMode ?? loadedPolicy.constraints?.installMode,
    installPreferOffline:
      input.installPreferOffline ?? loadedPolicy.constraints?.installPreferOffline,
    enforceFrozenLockfile:
      input.enforceFrozenLockfile ?? loadedPolicy.constraints?.enforceFrozenLockfile,
    workspace: workspace ?? loadedPolicy.constraints?.workspace,
  };
  const yarnMajor = pm === "yarn" ? await getYarnMajorVersion(cwd) : undefined;

  const refusal = checkPolicyAllowsBump(input, loadedPolicy);
  if (refusal) {
    return { kind: "result", result: refusal };
  }

  const located = locateDependency(input, commandConstraints);
  if ("result" in located) {
    return { kind: "result", result: located.result };
  }
  const { pkgPath, pkgJson, depField } = located;

  const currentRange = pkgJson[depField]![packageName]!;
  const newRange = computeNewRange(currentRange, fromVersion, toVersion);

  const commands: VersionBumpCommands = {
    install: resolveInstallCommand(pm, commandConstraints, yarnMajor),
    test: resolveProjectTestCommand(pm, commandConstraints, cwd),
    typecheck: resolveTypecheckCommand(pm, commandConstraints, cwd),
    dedupe: resolveDedupeCommand(pm, commandConstraints),
  };
  const shouldTypecheck = input.typecheck || Boolean(commandConstraints.typecheck);

  if (dryRun) {
    return {
      kind: "result",
      result: {
        packageName,
        strategy: "version-bump",
        fromVersion,
        toVersion,
        applied: false,
        dryRun: true,
        message: formatDryRunMessage({ input, commands, depField, currentRange, newRange }),
      },
    };
  }

  return {
    kind: "plan",
    plan: {
      pkgPath,
      pkgJson,
      depField,
      currentRange,
      newRange,
      loadedPolicy,
      commands,
      shouldTypecheck,
    },
  };
}

function checkPolicyAllowsBump(
  input: VersionBumpInput,
  policy: AutoremediatorPolicy,
): PatchResult | undefined {
  const { packageName, fromVersion, toVersion, dryRun } = input;
  if (!isPackageAllowed(policy, packageName)) {
    return {
      packageName,
      strategy: "none",
      fromVersion,
      toVersion,
      applied: false,
      dryRun,
      unresolvedReason: "policy-blocked",
      message: `Policy blocked changes for package "${packageName}".`,
    };
  }

  const isMajorBump =
    semver.valid(fromVersion) &&
    semver.valid(toVersion) &&
    semver.major(toVersion) > semver.major(fromVersion);

  if (isMajorBump && !policy.allowMajorBumps) {
    return {
      packageName,
      strategy: "none",
      fromVersion,
      toVersion,
      applied: false,
      dryRun,
      unresolvedReason: "major-bump-required",
      message: `Policy blocked major bump for "${packageName}" (${fromVersion} -> ${toVersion}).`,
    };
  }
  return undefined;
}

type LocatedDependency =
  | { pkgPath: string; pkgJson: RawPackageJson; depField: DepField }
  | { result: PatchResult };

/** Finds the manifest and field that declare the package; may narrow `constraints.workspace`. */
function locateDependency(
  input: VersionBumpInput,
  commandConstraints: { workspace?: string },
): LocatedDependency {
  const { cwd, packageName, fromVersion, dryRun, workspace } = input;
  let pkgPath = join(cwd, "package.json");
  let pkgJson: RawPackageJson;
  try {
    pkgJson = JSON.parse(readFileSync(pkgPath, "utf8")) as RawPackageJson;
  } catch {
    return {
      result: {
        packageName,
        strategy: "none",
        fromVersion,
        applied: false,
        dryRun,
        unresolvedReason: "package-json-not-found",
        message: `Could not read package.json at "${pkgPath}".`,
      },
    };
  }

  let depField = findDepField(pkgJson, packageName);

  if (!depField) {
    // Check monorepo child workspaces
    const declaringWorkspace = findDeclaringWorkspacePackage(cwd, packageName, workspace);
    if (declaringWorkspace) {
      pkgPath = declaringWorkspace.manifestPath;
      pkgJson = declaringWorkspace.manifest;
      depField = findDepField(pkgJson, packageName);
      commandConstraints.workspace = workspace ?? declaringWorkspace.name;
    }
  }

  if (!depField) {
    return {
      result: {
        packageName,
        strategy: "none",
        fromVersion,
        applied: false,
        dryRun,
        unresolvedReason: "transitive-dependency",
        message: `"${packageName}" was not found in package.json dependencies (it may be a transitive dependency). Cannot auto-bump.`,
      },
    };
  }
  return { pkgPath, pkgJson, depField };
}

function findDepField(pkgJson: RawPackageJson, packageName: string): DepField | undefined {
  return DEP_FIELDS.find((f) => pkgJson[f]?.[packageName] !== undefined);
}

/** Keeps the range prefix (^, ~, none) of the existing entry. */
function computeNewRange(currentRange: string, fromVersion: string, toVersion: string): string {
  const prefixMatch = /^([~^]?)/.exec(currentRange);
  const prefix = prefixMatch?.[1] ?? "";
  // A downgrade (pinning a release back) must be exact: the package manager keeps a locked newer
  // version that the old range still allows, so `^1.0.0` would change nothing.
  const isDowngrade =
    semver.valid(fromVersion) && semver.valid(toVersion) && semver.lt(toVersion, fromVersion);
  return isDowngrade ? toVersion : `${prefix}${toVersion}`;
}

interface DryRunDetails {
  input: VersionBumpInput;
  commands: VersionBumpCommands;
  depField: DepField;
  currentRange: string;
  newRange: string;
}

function formatDryRunMessage(details: DryRunDetails): string {
  const { input, commands, depField, currentRange, newRange } = details;
  const installCmd = commands.install.join(" ");
  const testCmd = commands.test.join(" ");
  const testPart = input.runTests ? ` and ${testCmd}` : "";
  const dedupePart =
    commands.dedupe.length > 0 ? ` and ${commands.dedupe.join(" ")} (best-effort)` : "";
  return `[DRY RUN] Would update ${depField}.${input.packageName}: "${currentRange}" -> "${newRange}", then run ${installCmd}${testPart}${dedupePart}.`;
}
