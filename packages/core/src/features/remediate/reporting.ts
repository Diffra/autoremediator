import type { EscalationAction } from "../../infra/policy/types.js";
import type {
  DependencyScope,
  DependencyScopeCounts,
  PatchStrategyCounts,
  UnresolvedReasonCounts,
} from "../../shared/types.js";
import type { CiSummary, ScanReport } from "./contracts.js";
import type {
  DispositionCounts,
  EscalationCounts,
  PatchResult,
  RemediationReport,
  SlaBreachEntry,
  SlaBreachSummary,
} from "./types.js";

export function buildStrategyCounts(reports: RemediationReport[]): PatchStrategyCounts | undefined {
  const counts: PatchStrategyCounts = {};

  for (const report of reports) {
    for (const result of report.results) {
      counts[result.strategy] = (counts[result.strategy] ?? 0) + 1;
    }
  }

  return Object.keys(counts).length > 0 ? counts : undefined;
}

export function toDependencyScope(installedType: "direct" | "transitive"): DependencyScope {
  return installedType === "direct" ? "direct" : "transitive";
}

export function buildDependencyScopeCounts(
  reports: RemediationReport[],
): DependencyScopeCounts | undefined {
  const counts: DependencyScopeCounts = {};

  for (const report of reports) {
    const packageScopes = new Map<string, DependencyScope>();

    for (const vulnerablePackage of report.vulnerablePackages) {
      const scope = toDependencyScope(vulnerablePackage.installed.type);
      const current = packageScopes.get(vulnerablePackage.installed.name);
      if (!current || current !== "direct") {
        packageScopes.set(vulnerablePackage.installed.name, scope);
      }
    }

    for (const result of report.results) {
      const scope = packageScopes.get(result.packageName);
      if (!scope) continue;
      counts[scope] = (counts[scope] ?? 0) + 1;
    }
  }

  return Object.keys(counts).length > 0 ? counts : undefined;
}

export function buildUnresolvedReasonCounts(
  reports: RemediationReport[],
): UnresolvedReasonCounts | undefined {
  const counts: UnresolvedReasonCounts = {};

  for (const report of reports) {
    for (const result of report.results) {
      if (!result.unresolvedReason) continue;
      counts[result.unresolvedReason] = (counts[result.unresolvedReason] ?? 0) + 1;
    }
  }

  return Object.keys(counts).length > 0 ? counts : undefined;
}

export function buildDispositionCounts(
  reports: RemediationReport[],
): DispositionCounts | undefined {
  const counts: DispositionCounts = {};

  for (const report of reports) {
    for (const result of report.results) {
      if (!result.disposition) continue;
      counts[result.disposition] = (counts[result.disposition] ?? 0) + 1;
    }
  }

  return Object.keys(counts).length > 0 ? counts : undefined;
}

export function buildEscalationCounts(results: PatchResult[]): EscalationCounts | undefined {
  const counts: EscalationCounts = {};

  for (const result of results) {
    if (!result.escalationAction) continue;
    counts[result.escalationAction] = (counts[result.escalationAction] ?? 0) + 1;
  }

  return Object.keys(counts).length > 0 ? counts : undefined;
}

export function buildSlaBreachSummary(reports: RemediationReport[]): SlaBreachSummary | undefined {
  const breaches: SlaBreachEntry[] = [];

  for (const report of reports) {
    if (!report.slaBreaches || report.slaBreaches.length === 0) continue;

    // Derive recommended action: first non-"none" escalationAction from any result in this report, else "open-issue"
    const recommendedAction: EscalationAction =
      report.results.map((r) => r.escalationAction).find((a) => a != null && a !== "none") ??
      "open-issue";

    for (const breach of report.slaBreaches) {
      breaches.push({
        cveId: breach.cveId,
        severity: breach.severity,
        hoursOverdue: breach.hoursOverdue,
        deadlineAt: breach.deadlineAt,
        recommendedAction,
      });
    }
  }

  return breaches.length > 0 ? { breachCount: breaches.length, breaches } : undefined;
}

export function toCiSummary(report: ScanReport): CiSummary {
  let remediationCount = 0;
  for (const cveReport of report.reports) {
    remediationCount += cveReport.results.length;
  }

  return {
    schemaVersion: report.schemaVersion,
    status: report.status,
    generatedAt: report.generatedAt,
    cveCount: report.cveIds.length,
    remediationCount,
    successCount: report.successCount,
    failedCount: report.failedCount,
    errors: report.errors,
    evidenceFile: report.evidenceFile,
    patchCount: report.patchCount || 0,
    patchValidationFailures: report.patchValidationFailures,
    strategyCounts: report.strategyCounts,
    dependencyScopeCounts: report.dependencyScopeCounts,
    unresolvedByReason: report.unresolvedByReason,
    escalationCounts:
      report.escalationCounts ??
      buildEscalationCounts(
        report.reports.flatMap((remediationReport) => remediationReport.results),
      ),
    patchesDir: report.patchesDir,
    correlation: report.correlation,
    provenance: report.provenance,
    constraints: report.constraints,
    idempotencyKey: report.idempotencyKey,
    llmUsageCount: report.llmUsageCount,
    totalInputTokens: report.totalInputTokens,
    totalOutputTokens: report.totalOutputTokens,
    totalLlmLatencyMs: report.totalLlmLatencyMs,
    slaBreaches: report.slaBreaches,
    slaBreachSummary: buildSlaBreachSummary(report.reports),
    dispositionCounts: report.dispositionCounts,
    simulationSummary: report.simulationSummary,
  };
}

/**
 * Process exit codes a pipeline or an agent can branch on. `0` and `1` keep their old meaning;
 * the others split what used to be a single failure code so the caller knows what to do next.
 */
export const EXIT_CODES = {
  /** Everything fixed, or nothing to do. */
  ok: 0,
  /** Failed, nothing was fixed. */
  failed: 1,
  /** Some results were fixed and some failed. */
  partial: 2,
  /** The only unfinished results are held for a human to approve. */
  needsApproval: 3,
  /** The only unfinished results are forbidden by policy (deny list, no major bumps, ...). */
  policyBlocked: 4,
} as const;

/** Reasons that mean "a person must approve this", as opposed to "policy forbids this". */
const APPROVAL_REASONS = ["policy-blocked"] as const;
const POLICY_REASONS = ["constraint-blocked", "major-bump-required"] as const;

function countReasons(counts: CiSummary["unresolvedByReason"], reasons: readonly string[]): number {
  let total = 0;
  for (const reason of reasons) {
    total += (counts as Record<string, number> | undefined)?.[reason] ?? 0;
  }
  return total;
}

/**
 * Map a run summary to an exit code. A genuine failure outranks the other two: a run that
 * failed on something and is also waiting for approval is reported as failed (or partial), because
 * approving would not finish it.
 */
export function ciExitCode(summary: CiSummary): number {
  if (summary.failedCount <= 0) return EXIT_CODES.ok;
  const held = countReasons(summary.unresolvedByReason, APPROVAL_REASONS);
  const blocked = countReasons(summary.unresolvedByReason, POLICY_REASONS);
  const other = summary.failedCount - held - blocked;
  if (other > 0) return summary.successCount > 0 ? EXIT_CODES.partial : EXIT_CODES.failed;
  return held > 0 ? EXIT_CODES.needsApproval : EXIT_CODES.policyBlocked;
}
