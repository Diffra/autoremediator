/** Dry-run and preview simulation: what a run would have changed, and what could go wrong. */
import type { DependencyScope } from "../../shared/types.js";
import { toDependencyScope } from "./reporting.js";
import type {
  RemediateOptions,
  PatchResult,
  RemediationReport,
  ResultSimulation,
  SimulationMutation,
  SimulationMutationTarget,
  SimulationRebuttalCode,
  SimulationRebuttalFinding,
  SimulationSummary,
} from "./types.js";

const SIMULATION_MUTATION_REASONS: Record<SimulationMutationTarget, string> = {
  "package-manifest": "Would update the package manifest dependency declaration.",
  lockfile: "Would update the dependency lockfile to reflect resolved versions.",
  "patch-file": "Would write a generated patch artifact.",
  "patch-manifest": "Would write patch artifact manifest metadata.",
  "install-state": "Would refresh installed dependency state.",
  "test-command": "Would execute the configured test command.",
};

const SIMULATION_REBUTTAL_MESSAGES: Record<SimulationRebuttalCode, string> = {
  "unresolved-reason": "The remediation remains unresolved in simulation mode.",
  "policy-blocked": "Policy would block this remediation from being applied.",
  "validation-risk": "Validation signals indicate this remediation may fail or be unsafe.",
  "low-confidence": "Patch confidence is below the acceptance threshold.",
  "high-risk-patch": "This remediation path is classified as high risk.",
  "transitive-target": "This result targets a transitive dependency.",
  "escalation-planned": "This remediation is planned for escalation instead of direct apply.",
  "exploit-signal": "Exploit-signal prioritization was triggered for this CVE.",
  "sla-breach": "This CVE breaches the configured remediation SLA.",
  "tests-not-run": "Tests would not run for this mutating remediation path.",
};

function getSimulationMode(
  options: Pick<RemediateOptions, "dryRun" | "preview" | "simulationMode">,
): ResultSimulation["mode"] | undefined {
  if (!options.simulationMode) {
    return undefined;
  }

  if (options.preview === true) {
    return "preview";
  }

  if (options.dryRun === true) {
    return "dry-run";
  }

  return undefined;
}

export function assertValidSimulationMode(
  options: Pick<RemediateOptions, "dryRun" | "preview" | "simulationMode">,
): void {
  if (options.simulationMode !== true) {
    return;
  }

  if (!getSimulationMode(options)) {
    throw new Error("simulationMode requires dryRun=true or preview=true.");
  }
}

function createDependencyScopeLookup(report: RemediationReport): Map<string, DependencyScope> {
  const scopes = new Map<string, DependencyScope>();

  for (const vulnerablePackage of report.vulnerablePackages) {
    const scope = toDependencyScope(vulnerablePackage.installed.type);
    const current = scopes.get(vulnerablePackage.installed.name);
    if (!current || current !== "direct") {
      scopes.set(vulnerablePackage.installed.name, scope);
    }
  }

  return scopes;
}

function createSimulationMutation(
  target: SimulationMutationTarget,
  path?: string,
): SimulationMutation {
  return {
    target,
    reason: SIMULATION_MUTATION_REASONS[target],
    ...(path ? { path } : {}),
  };
}

function buildPlannedMutations(result: PatchResult, runTests: boolean): SimulationMutation[] {
  if (result.strategy === "version-bump" || result.strategy === "override") {
    return [
      createSimulationMutation("package-manifest"),
      createSimulationMutation("lockfile"),
      createSimulationMutation("install-state"),
      ...(runTests ? [createSimulationMutation("test-command")] : []),
    ];
  }

  if (result.strategy === "patch-file") {
    const patchFilePath = result.patchArtifact?.patchFilePath ?? result.patchFilePath;
    const manifestFilePath = result.patchArtifact?.manifestFilePath;

    return [
      createSimulationMutation("patch-file", patchFilePath),
      ...(manifestFilePath ? [createSimulationMutation("patch-manifest", manifestFilePath)] : []),
      createSimulationMutation("install-state"),
      ...(runTests ? [createSimulationMutation("test-command")] : []),
    ];
  }

  return [];
}

function addRebuttalFinding(
  findings: Map<SimulationRebuttalCode, SimulationRebuttalFinding>,
  code: SimulationRebuttalCode,
  severity: SimulationRebuttalFinding["severity"],
  sourceSignals: string[],
): void {
  const existing = findings.get(code);
  if (existing) {
    existing.sourceSignals = [...new Set([...existing.sourceSignals, ...sourceSignals])];
    return;
  }

  findings.set(code, {
    code,
    severity,
    message: SIMULATION_REBUTTAL_MESSAGES[code],
    sourceSignals: [...new Set(sourceSignals)],
  });
}

function hasValidationRisk(result: PatchResult): boolean {
  return (
    result.validation?.passed === false ||
    result.validationPhases?.some((phase) => !phase.passed) === true ||
    result.patchArtifact?.validationPhases?.some((phase) => !phase.passed) === true
  );
}

function buildRebuttalFindings(params: {
  report: RemediationReport;
  result: PatchResult;
  dependencyScope?: DependencyScope;
  wouldMutate: boolean;
  runTests: boolean;
}): SimulationRebuttalFinding[] {
  const findings = new Map<SimulationRebuttalCode, SimulationRebuttalFinding>();
  const { report, result, dependencyScope, wouldMutate, runTests } = params;

  if (result.unresolvedReason) {
    addRebuttalFinding(findings, "unresolved-reason", "warning", ["unresolvedReason"]);
  }

  if (result.unresolvedReason === "policy-blocked") {
    addRebuttalFinding(findings, "policy-blocked", "high", ["unresolvedReason"]);
  }

  if (hasValidationRisk(result)) {
    addRebuttalFinding(findings, "validation-risk", "high", ["validation", "validationPhases"]);
  }

  if (
    result.unresolvedReason === "patch-confidence-too-low" ||
    result.dispositionReason === "low-confidence"
  ) {
    addRebuttalFinding(findings, "low-confidence", "warning", [
      ...(result.unresolvedReason === "patch-confidence-too-low" ? ["unresolvedReason"] : []),
      ...(result.dispositionReason === "low-confidence" ? ["dispositionReason"] : []),
    ]);
  }

  if (result.riskLevel === "high") {
    addRebuttalFinding(findings, "high-risk-patch", "warning", ["riskLevel"]);
  }

  if (dependencyScope === "transitive") {
    addRebuttalFinding(findings, "transitive-target", "info", ["dependencyScope"]);
  }

  if (result.escalationAction && result.escalationAction !== "none") {
    addRebuttalFinding(findings, "escalation-planned", "warning", ["escalationAction"]);
  }

  if (report.exploitSignalTriggered === true) {
    addRebuttalFinding(findings, "exploit-signal", "high", ["exploitSignalTriggered"]);
  }

  if ((report.slaBreaches?.length ?? 0) > 0) {
    addRebuttalFinding(findings, "sla-breach", "warning", ["slaBreaches"]);
  }

  if (wouldMutate && !runTests) {
    addRebuttalFinding(findings, "tests-not-run", "warning", ["runTests"]);
  }

  return [...findings.values()];
}

export function buildResultSimulation(
  report: RemediationReport,
  result: PatchResult,
  options: Pick<RemediateOptions, "dryRun" | "preview" | "runTests" | "simulationMode">,
): ResultSimulation | undefined {
  const mode = getSimulationMode(options);
  if (!mode) {
    return undefined;
  }

  const dependencyScopeLookup = createDependencyScopeLookup(report);
  const dependencyScope = result.dependencyScope ?? dependencyScopeLookup.get(result.packageName);
  const plannedMutations = buildPlannedMutations(result, options.runTests === true);
  const wouldMutate = plannedMutations.length > 0;

  let unifiedDiff: string | undefined;
  if (result.patchArtifact?.patchFilePath) {
    unifiedDiff = `--- ${result.patchArtifact.patchFilePath}\n+++ ${result.patchArtifact.patchFilePath}`;
  } else if (result.strategy === "version-bump" && result.toVersion) {
    unifiedDiff = `--- package.json\n+++ package.json\n@@ -1,3 +1,3 @@\n-    "${result.packageName}": "${result.fromVersion}"\n+    "${result.packageName}": "^${result.toVersion}"`;
  } else if (result.strategy === "override" && result.toVersion) {
    unifiedDiff = `--- package.json\n+++ package.json\n@@ -1,3 +1,3 @@\n+  "overrides": {\n+    "${result.packageName}": "${result.toVersion}"\n+  }`;
  }

  return {
    mode,
    wouldMutate,
    plannedMutations,
    rebuttalFindings: buildRebuttalFindings({
      report,
      result,
      dependencyScope,
      wouldMutate,
      runTests: options.runTests === true,
    }),
    unifiedDiff,
  };
}

export function buildSimulationSummary(
  reports: RemediationReport[],
): SimulationSummary | undefined {
  let mode: SimulationSummary["mode"] | undefined;
  let resultCount = 0;
  let wouldMutateCount = 0;
  let rebuttalResultCount = 0;
  const plannedMutationCounts: Partial<Record<SimulationMutationTarget, number>> = {};
  const rebuttalCounts: Partial<Record<SimulationRebuttalCode, number>> = {};

  for (const report of reports) {
    for (const result of report.results) {
      if (!result.simulation) {
        continue;
      }

      mode ??= result.simulation.mode;
      resultCount += 1;
      if (result.simulation.wouldMutate) {
        wouldMutateCount += 1;
      }
      if (result.simulation.rebuttalFindings.length > 0) {
        rebuttalResultCount += 1;
      }

      for (const mutation of result.simulation.plannedMutations) {
        plannedMutationCounts[mutation.target] = (plannedMutationCounts[mutation.target] ?? 0) + 1;
      }

      for (const finding of result.simulation.rebuttalFindings) {
        rebuttalCounts[finding.code] = (rebuttalCounts[finding.code] ?? 0) + 1;
      }
    }
  }

  if (!mode) {
    return undefined;
  }

  return {
    mode,
    resultCount,
    wouldMutateCount,
    nonMutatingCount: resultCount - wouldMutateCount,
    rebuttalResultCount,
    plannedMutationCounts:
      Object.keys(plannedMutationCounts).length > 0 ? plannedMutationCounts : undefined,
    rebuttalCounts: Object.keys(rebuttalCounts).length > 0 ? rebuttalCounts : undefined,
  };
}

export function applySimulationMetadata(
  report: RemediationReport,
  options: Pick<RemediateOptions, "dryRun" | "preview" | "runTests" | "simulationMode">,
): RemediationReport {
  const mode = getSimulationMode(options);
  if (!mode) {
    return report;
  }

  const enrichedReport: RemediationReport = {
    ...report,
    results: report.results.map((result) => ({
      ...result,
      simulation: buildResultSimulation(report, result, options),
    })),
  };

  return {
    ...enrichedReport,
    simulationSummary: buildSimulationSummary([enrichedReport]),
  };
}
