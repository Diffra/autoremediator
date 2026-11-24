/** Remediates one vulnerable installed package for one CVE: gates first, then fix, then fallback. */
import { isPackageAllowed } from "../../../infra/policy/policy.js";
import type { AutoremediatorPolicy } from "../../../infra/policy/policy.js";
import type { createProjectSnapshot } from "../../../infra/rollback/rollback.js";
import type { CveDetails, VulnerablePackage } from "../../intelligence/types.js";
import {
  findMaintainerVex,
  readInstalledMaintainerVex,
  type MaintainerVexIndex,
} from "../../maintainer-vex/index.js";
import {
  type loadMemoryConstraints,
  pinnedMessage,
  rejectedMessage,
} from "../../memory/consume.js";
import type { PatchGenerator } from "../../patch/patch-generator.js";
import { assessPackageReachability } from "../../reachability/check-reachability.js";
import { computeEscalationAction } from "../escalation.js";
import type { LlmUsageMetrics, PatchResult, RemediateOptions } from "../types.js";
import { applyDispositionAndContainment } from "./disposition.js";
import { shouldAttemptPatchFallback, tryPatchFallback } from "./fallback.js";
import type { LocalRunOptions } from "./options.js";
import { resolvePrimaryResult } from "./primary-strategy.js";
import type { SecOpsPreflightResult } from "./secops-preflight.js";

/** What every package of one CVE run shares. */
export interface PackageRunContext {
  cveId: string;
  cveDetails: CveDetails;
  options: RemediateOptions;
  resolved: LocalRunOptions;
  policy: AutoremediatorPolicy;
  memory: ReturnType<typeof loadMemoryConstraints> | undefined;
  preflight: Pick<
    Extract<SecOpsPreflightResult, { suppressed: false }>,
    "exploitSignalTriggered" | "slaBreaches"
  >;
  getGenerator: () => Promise<PatchGenerator | undefined>;
  /** The VEX documents installed packages ship, read once and only when something is vulnerable. */
  shippedVex?: MaintainerVexIndex;
}

export interface PackageOutcome {
  result: PatchResult;
  usage?: LlmUsageMetrics[];
}

type Snapshot = Awaited<ReturnType<typeof createProjectSnapshot>>;
type MaintainerClaim = ReturnType<typeof findMaintainerVex>["evidence"][number];

const scopeOf = (vulnerable: VulnerablePackage): "direct" | "transitive" =>
  vulnerable.installed.type === "direct" ? "direct" : "transitive";

/** A result with nothing applied, in the shape every gate below shares. */
function notApplied(
  vulnerable: VulnerablePackage,
  dryRun: boolean,
  rest: Partial<PatchResult> & { message: string },
): PatchResult {
  return {
    packageName: vulnerable.installed.name,
    fromVersion: vulnerable.installed.version,
    strategy: "none",
    applied: false,
    dryRun,
    ...rest,
  };
}

/** The gates that stop a package before any fix is tried, as the result that says so. */
function gateResult(
  context: PackageRunContext,
  vulnerable: VulnerablePackage,
  maintainerClaim: MaintainerClaim | undefined,
): { result: PatchResult; finalize: boolean } | undefined {
  const { resolved, policy, memory, cveId } = context;
  const { dryRun } = resolved;
  const name = vulnerable.installed.name;

  if (!isPackageAllowed(policy, name)) {
    return {
      finalize: true,
      result: notApplied(vulnerable, dryRun, {
        unresolvedReason: "policy-blocked",
        message: `Policy denyPackages blocked changes for package "${name}".`,
      }),
    };
  }
  // A person's pin comes first: the package is left alone whatever else says.
  const pinned = memory?.pinned.get(name);
  if (pinned) {
    return {
      finalize: true,
      result: notApplied(vulnerable, dryRun, {
        unresolvedReason: "constraint-blocked",
        message: pinnedMessage(pinned),
      }),
    };
  }
  // Opt-in only: by default the maintainer's verdict is evidence and remediation goes ahead.
  if (resolved.trustMaintainerVex && maintainerClaim) {
    const { maintainer } = maintainerClaim;
    const impact = maintainerClaim.impactStatement ? `. ${maintainerClaim.impactStatement}` : "";
    return {
      finalize: false,
      result: notApplied(vulnerable, dryRun, {
        dependencyScope: scopeOf(vulnerable),
        suppressedBy: {
          justification: "not_affected",
          source: "maintainer-vex",
          notes: `${maintainer.name}@${maintainer.version} (${maintainerClaim.author}): ${maintainerClaim.justification}${impact}`,
        },
        message: `Suppressed by maintainer VEX: ${maintainer.name}@${maintainer.version} (author ${maintainerClaim.author}) declares not_affected (${maintainerClaim.justification}) for ${cveId}.`,
      }),
    };
  }
  if (resolved.skipUnreachable) {
    const reach = assessPackageReachability(resolved.cwd, name);
    if (reach.status === "not-reachable") {
      return {
        finalize: true,
        result: notApplied(vulnerable, dryRun, {
          message: `Skipped: '${name}' is not reachable from source code.`,
          reachability: reach,
        }),
      };
    }
  }
  return undefined;
}

function primaryFor(context: PackageRunContext, vulnerable: VulnerablePackage) {
  const { resolved, options, memory } = context;
  return resolvePrimaryResult({
    vulnerable,
    cwd: resolved.cwd,
    packageManager: resolved.packageManager,
    dryRun: resolved.dryRun,
    policy: resolved.policy,
    runTests: resolved.runTests,
    constraints: resolved.constraints,
    proofOfFix: resolved.proofOfFix,
    requireProofOfFix: resolved.requireProofOfFix,
    reproductionTest: options.reproductionTest,
    patchesDir: resolved.patchesDir,
    offlineIntelligence: resolved.offlineIntelligence,
    rejectedVersions: new Map(
      [...(memory?.rejected.get(vulnerable.installed.name) ?? [])].map(([version, entry]) => [
        version,
        rejectedMessage(entry),
      ]),
    ),
  });
}

function fallbackFor(context: PackageRunContext, vulnerable: VulnerablePackage) {
  const { resolved, options, cveId, cveDetails } = context;
  const { constraints } = resolved;
  return tryPatchFallback({
    cwd: resolved.cwd,
    packageManager: resolved.packageManager,
    packageName: vulnerable.installed.name,
    vulnerableVersion: vulnerable.installed.version,
    cveId,
    cveSummary: cveDetails.summary ?? cveId,
    dependencyScope: scopeOf(vulnerable),
    dryRun: resolved.dryRun,
    runTests: resolved.runTests,
    patchesDir: resolved.patchesDir,
    getGenerator: context.getGenerator,
    policy: options.policy,
    patchConfidenceThresholds: resolved.patchConfidenceThresholds,
    installMode: constraints.installMode,
    installPreferOffline: constraints.installPreferOffline,
    enforceFrozenLockfile: constraints.enforceFrozenLockfile,
    workspace: constraints.workspace,
    vulnerableRange: vulnerable.affected.vulnerableRange,
    proofOfFix: resolved.proofOfFix,
    requireProofOfFix: resolved.requireProofOfFix,
  });
}

/** Fixes one vulnerable package, or says why it was left alone. */
export async function remediateVulnerable(
  context: PackageRunContext,
  vulnerable: VulnerablePackage,
  snapshot: Snapshot,
): Promise<PackageOutcome> {
  const { resolved, policy, cveId, cveDetails, preflight } = context;
  const { cwd, constraints } = resolved;

  context.shippedVex ??= readInstalledMaintainerVex(cwd);
  const maintainerVex = findMaintainerVex(context.shippedVex, cveId, vulnerable.installed);
  const withMaintainerVex = (result: PatchResult): PatchResult => ({
    ...result,
    ...(maintainerVex.evidence.length > 0 ? { maintainerVex: maintainerVex.evidence } : {}),
    ...(maintainerVex.ignored.length > 0 ? { maintainerVexIgnored: maintainerVex.ignored } : {}),
  });
  const finalize = (result: PatchResult): PatchResult => {
    const withDisposition = applyDispositionAndContainment(result, {
      exploitSignalTriggered: preflight.exploitSignalTriggered,
      slaBreaches: preflight.slaBreaches,
      severity: cveDetails.severity,
      policy: context.options.dispositionPolicy ?? policy.dispositionPolicy,
      containmentMode: context.options.containmentMode ?? policy.containmentMode ?? false,
      cwd,
      snapshot,
    });
    if (withDisposition.unresolvedReason) {
      withDisposition.escalationAction = computeEscalationAction(
        withDisposition.unresolvedReason,
        resolved.escalationGraph,
      );
    }
    return withMaintainerVex(withDisposition);
  };

  const gate = gateResult(context, vulnerable, maintainerVex.evidence[0]);
  if (gate) {
    return { result: gate.finalize ? finalize(gate.result) : withMaintainerVex(gate.result) };
  }

  const primary = await primaryFor(context, vulnerable);
  if (shouldAttemptPatchFallback(primary.result, constraints.preferVersionBump ?? false)) {
    const fallback = await fallbackFor(context, vulnerable);
    return { result: finalize(fallback.result), usage: fallback.usage };
  }
  return { result: finalize({ ...primary.result, dependencyScope: scopeOf(vulnerable) }) };
}
