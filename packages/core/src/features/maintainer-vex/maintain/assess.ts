/** Decides, for one advisory, whether the maintained package is affected and what would fix it. */
import type { RemediationReport } from "../../remediate/types.js";
import type { MaintainDeps } from "./deps.js";
import { isShipped, scopeOf, type ProjectLocks } from "./scope.js";
import type {
  MaintainAdvisory,
  MaintainOptions,
  MaintainPackageFinding,
  MaintainPlanSummary,
} from "./types.js";

export async function assess(
  id: string,
  options: MaintainOptions,
  cwd: string,
  locks: ProjectLocks,
  deps: MaintainDeps,
): Promise<MaintainAdvisory> {
  const report = await deps.plan(id, {
    cwd,
    source: options.source ?? "sdk",
    ...(options.policy ? { policy: options.policy } : {}),
    ...(options.packageManager ? { packageManager: options.packageManager } : {}),
    ...(options.offlineIntelligence ? { offlineIntelligence: true } : {}),
    ...(options.intelligenceSnapshotPath
      ? { intelligenceSnapshotPath: options.intelligenceSnapshotPath }
      : {}),
    // A recorded plan is a write under .autoremediator/, so only with approval.
    evidence: options.yes === true,
  });
  const severity = report.cveDetails?.severity;
  if (!report.cveDetails) {
    return { id, decision: "unknown", reason: report.summary, packages: [] };
  }

  const packages = await findPackages(report, options, cwd, locks, deps);
  const plan = summarizePlan(report);
  const base = { id, ...(severity ? { severity } : {}), packages, ...(plan ? { plan } : {}) };
  return { ...base, ...decide(packages, options) };
}

async function findPackages(
  report: RemediationReport,
  options: MaintainOptions,
  cwd: string,
  locks: ProjectLocks,
  deps: MaintainDeps,
): Promise<MaintainPackageFinding[]> {
  const packages: MaintainPackageFinding[] = [];
  const seen = new Set<string>();
  for (const { installed } of report.vulnerablePackages) {
    const key = `${installed.name}@${installed.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const scope = scopeOf(cwd, locks, installed.name, installed.version);
    const finding: MaintainPackageFinding = {
      name: installed.name,
      version: installed.version,
      scope,
    };
    if (isShipped(finding)) {
      const reach = await deps.reachability({
        cwd,
        packageName: installed.name,
        ...(options.traceFile ? { traceFile: options.traceFile } : {}),
      });
      finding.reachability = reach.status;
      finding.reason = reach.reason;
      if (reach.evidenceKind) finding.evidenceKind = reach.evidenceKind;
      if (reach.runtime) finding.runtimeVerdict = reach.runtime.verdict;
    }
    packages.push(finding);
  }
  return packages;
}

function decide(
  packages: readonly MaintainPackageFinding[],
  options: MaintainOptions,
): Pick<MaintainAdvisory, "decision" | "reason"> {
  const shipped = packages.filter((entry) => isShipped(entry));
  if (shipped.length === 0) {
    return {
      decision: "not-shipped",
      reason:
        packages.length === 0
          ? "No installed package matches the advisory."
          : "Only development or unreferenced dependencies match; consumers do not install them.",
    };
  }
  const names = shipped.map((entry) => entry.name).join(", ");
  const reachable = shipped.filter((entry) => entry.reachability === "reachable");
  if (reachable.length > 0) {
    return {
      decision: "affected",
      reason: `This package reaches ${reachable.map((entry) => entry.name).join(", ")}: ${reachable[0]!.reason ?? "reachable"}`,
    };
  }
  const unknown = shipped.filter((entry) => entry.reachability !== "not-reachable");
  if (unknown.length > 0) {
    return {
      decision: "under_investigation",
      reason: `Reachability of ${unknown.map((entry) => entry.name).join(", ")} could not be decided.`,
    };
  }
  if (options.assertNotAffected) {
    return {
      decision: "not_affected",
      reason: `Asserted by the author: the static scan found no use of ${names}.`,
    };
  }
  return {
    decision: "under_investigation",
    reason: `The static scan found no use of ${names}, but not_affected is only written with assertNotAffected (--assert-not-affected) after you have reviewed it.`,
  };
}

function summarizePlan(report: RemediationReport): MaintainPlanSummary | undefined {
  const items = report.results
    .filter(
      (result) =>
        result.toVersion && (result.strategy === "version-bump" || result.strategy === "override"),
    )
    .map((result) => ({
      packageName: result.packageName,
      fromVersion: result.fromVersion,
      toVersion: result.toVersion!,
    }));
  if (items.length === 0 && !report.runId) return undefined;
  return {
    ...(report.runId ? { runId: report.runId } : {}),
    ...(report.planId ? { planId: report.planId } : {}),
    items,
    skipped: report.results.length - items.length,
  };
}
