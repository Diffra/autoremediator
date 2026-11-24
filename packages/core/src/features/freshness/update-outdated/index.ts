import {
  detectPackageManager,
  getYarnMajorVersion,
  resolveInstallCommand,
  type PackageManager,
} from "../../../infra/package-manager/index.js";
import { loadPolicy } from "../../../infra/policy/policy.js";
import { errorMessage } from "../../../shared/errors.js";
import { assertAutonomyAllows } from "../../autonomy/index.js";
import {
  assertChangeRequestAllowed,
  createChangeRequestsForReports,
} from "../../change-request/index.js";
import {
  addEvidenceStep,
  createEvidenceLog,
  finalizeEvidence,
  writeEvidenceLog,
} from "../../evidence/log.js";
import { queryOutdatedPackages } from "../../intelligence/sources/registry.js";
import { loadMemoryConstraints } from "../../memory/consume.js";
import { resolveProjectTestCommand } from "../../memory/test-command.js";
import {
  resolveConstraints,
  resolveCorrelationContext,
  resolveProvenanceContext,
} from "../../remediate/context.js";
import { applyBump } from "./bump.js";
import type { OutdatedPackage, UpdateOutdatedOptions, UpdateOutdatedReport } from "./types.js";

// ---------------------------------------------------------------------------
// Public function
// ---------------------------------------------------------------------------

export async function updateOutdated(
  options: UpdateOutdatedOptions = {},
): Promise<UpdateOutdatedReport> {
  const { cwd, policy, correlation, provenance, constraints, evidence } = beginRun(options);

  // Query outdated packages
  let outdatedMap: Awaited<ReturnType<typeof queryOutdatedPackages>>;
  try {
    outdatedMap = await queryOutdatedPackages(cwd, {
      includeTransitive: options.includeTransitive ?? false,
      packageManager: options.packageManager,
    });
  } catch (err) {
    return failedQueryReport(err, { cwd, options, evidence, constraints, correlation, provenance });
  }

  const outdatedPackages = toOutdatedPackages(outdatedMap);

  addEvidenceStep(
    evidence,
    "update-outdated.registry-query",
    {},
    { packageCount: outdatedPackages.length },
  );

  // Resolve install/test commands once (before the loop)
  const pm = options.packageManager ?? detectPackageManager(cwd);
  const yarnMajor = pm === "yarn" ? await getYarnMajorVersion(cwd) : undefined;
  const installCommand = resolveInstallCommand(pm, constraints, yarnMajor);
  const testCommand = resolveProjectTestCommand(pm, constraints, cwd);

  const memory = options.ignoreMemory ? undefined : loadMemoryConstraints(cwd);
  let successCount = 0;
  let failedCount = 0;
  let skippedCount = 0;
  const errors: Array<{ packageName: string; message: string }> = [];

  for (const [packageName, info] of outdatedMap) {
    const outcome = await updateOne(packageName, info, {
      cwd,
      options,
      policy,
      memory,
      evidence,
      pm,
      installCommand,
      testCommand,
    });
    if (outcome.kind === "skipped") skippedCount++;
    if (outcome.kind === "success") successCount++;
    if (outcome.kind === "failed") {
      failedCount++;
      errors.push({ packageName, message: outcome.message });
    }
  }

  const status = reportStatus(failedCount, successCount);

  evidence.summary = {
    status,
    cveCount: 0,
    remediationCount: successCount + failedCount + skippedCount,
    successCount,
    failedCount,
    patchCount: 0,
  };

  finalizeEvidence(evidence);
  const evidenceFile = options.evidence === false ? undefined : writeEvidenceLog(cwd, evidence);

  const changeRequests = await openChangeRequests(cwd, options, outdatedPackages, successCount);

  return {
    schemaVersion: "1.0",
    status,
    generatedAt: new Date().toISOString(),
    outdatedPackages,
    successCount,
    failedCount,
    skippedCount,
    errors,
    evidenceFile,
    patchCount: 0,
    constraints,
    correlation,
    provenance,
    changeRequests,
  };
}

function reportStatus(failedCount: number, successCount: number): UpdateOutdatedReport["status"] {
  if (failedCount === 0) {
    return "ok";
  }
  return successCount > 0 ? "partial" : "failed";
}

type OutdatedInfo =
  Awaited<ReturnType<typeof queryOutdatedPackages>> extends Map<string, infer Info> ? Info : never;

interface UpdateContext {
  cwd: string;
  options: UpdateOutdatedOptions;
  policy: ReturnType<typeof loadPolicy>;
  memory: ReturnType<typeof loadMemoryConstraints> | undefined;
  evidence: ReturnType<typeof createEvidenceLog>;
  pm: PackageManager;
  installCommand: string[];
  testCommand: string[];
}

type UpdateOutcome =
  | { kind: "skipped" }
  | { kind: "success" }
  | { kind: "failed"; message: string };

/** Updates one package, or says why it was left alone; every decision goes to the evidence log. */
async function updateOne(
  packageName: string,
  info: OutdatedInfo,
  context: UpdateContext,
): Promise<UpdateOutcome> {
  const { cwd, options, policy, memory, evidence, pm, installCommand, testCommand } = context;

  // Skip major bumps when policy disallows them
  if (info.isMajorBump && !policy.allowMajorBumps) {
    addEvidenceStep(
      evidence,
      "update-outdated.skip",
      { packageName, reason: "major-bump-not-allowed" },
      {},
    );
    return { kind: "skipped" };
  }

  // A package a person pinned in the repository's memory is left alone.
  const pinned = memory?.pinned.get(packageName);
  if (pinned) {
    addEvidenceStep(
      evidence,
      "update-outdated.skip",
      { packageName, reason: "pinned-by-memory", entry: pinned.id, why: pinned.reason },
      {},
    );
    return { kind: "skipped" };
  }

  // In dry-run mode, count as success but do not write
  if (options.dryRun) {
    addEvidenceStep(
      evidence,
      "update-outdated.dry-run",
      { packageName, fromVersion: info.currentVersion, toVersion: info.latestVersion },
      {},
    );
    return { kind: "success" };
  }

  addEvidenceStep(evidence, "update-outdated.apply", {
    packageName,
    fromVersion: info.currentVersion,
    toVersion: info.latestVersion,
  });

  const result = await applyBump({
    cwd,
    packageName,
    fromVersion: info.currentVersion,
    toVersion: info.latestVersion,
    pm,
    installCommand,
    testCommand,
    runTests: options.runTests ?? false,
  });

  if (result.applied) {
    addEvidenceStep(
      evidence,
      "update-outdated.apply.success",
      { packageName },
      { toVersion: info.latestVersion },
    );
    return { kind: "success" };
  }
  addEvidenceStep(
    evidence,
    "update-outdated.apply.failed",
    { packageName },
    { error: result.message },
  );
  return { kind: "failed", message: result.message };
}

/** The report for a run that could not even ask the registry what is outdated. */
function failedQueryReport(
  err: unknown,
  context: {
    cwd: string;
    options: UpdateOutdatedOptions;
    evidence: ReturnType<typeof createEvidenceLog>;
    constraints: ReturnType<typeof resolveConstraints>;
    correlation: ReturnType<typeof resolveCorrelationContext>;
    provenance: ReturnType<typeof resolveProvenanceContext>;
  },
): UpdateOutdatedReport {
  const { cwd, options, evidence, constraints, correlation, provenance } = context;
  addEvidenceStep(
    evidence,
    "update-outdated.registry-query-failed",
    {},
    { error: errorMessage(err) },
  );
  finalizeEvidence(evidence);
  const evidenceFile = options.evidence === false ? undefined : writeEvidenceLog(cwd, evidence);

  return {
    schemaVersion: "1.0",
    status: "failed",
    generatedAt: new Date().toISOString(),
    outdatedPackages: [],
    successCount: 0,
    failedCount: 1,
    skippedCount: 0,
    errors: [{ packageName: "*", message: errorMessage(err) }],
    evidenceFile,
    patchCount: 0,
    constraints,
    correlation,
    provenance,
  };
}

/** One change request for the plain version bumps, when asked for and something was updated. */
function openChangeRequests(
  cwd: string,
  options: UpdateOutdatedOptions,
  outdatedPackages: OutdatedPackage[],
  successCount: number,
) {
  return options.changeRequest?.enabled && successCount > 0
    ? createChangeRequestsForReports({
        cwd,
        options: options.changeRequest,
        reports: [
          {
            cveId: "UPDATE-OUTDATED",
            cveDetails: null,
            vulnerablePackages: [],
            results: outdatedPackages
              .filter((pkg) => !pkg.isMajorBump)
              .map((pkg) => ({
                packageName: pkg.name,
                strategy: "version-bump" as const,
                fromVersion: pkg.currentVersion,
                toVersion: pkg.latestVersion,
                applied: true,
                dryRun: Boolean(options.dryRun),
                message: `Updated ${pkg.name} to ${pkg.latestVersion}`,
              })),
            summary: "update-outdated",
          },
        ],
      })
    : undefined;
}

/** Checks the options, loads the policy once and opens the evidence log for the run. */
function beginRun(options: UpdateOutdatedOptions) {
  assertChangeRequestAllowed(options);
  const cwd = options.cwd ?? process.cwd();

  // Load policy exactly once
  const policy = loadPolicy(cwd, options.policy);
  if (!options.dryRun) assertAutonomyAllows(cwd, options.policy, "apply", "updateOutdated");
  const correlation = resolveCorrelationContext(options);
  const provenance = resolveProvenanceContext(options);
  const constraints = resolveConstraints(options, cwd);

  const evidence = createEvidenceLog(cwd, [], {
    requestId: correlation.requestId,
    sessionId: correlation.sessionId,
    parentRunId: correlation.parentRunId,
    actor: provenance.actor,
    source: provenance.source,
  });

  addEvidenceStep(evidence, "update-outdated.start", {
    cwd,
    includeTransitive: options.includeTransitive ?? false,
    dryRun: options.dryRun ?? false,
  });
  return { cwd, policy, correlation, provenance, constraints, evidence };
}

function toOutdatedPackages(outdatedMap: Awaited<ReturnType<typeof queryOutdatedPackages>>) {
  return [...outdatedMap.entries()].map(([name, info]) => ({
    name,
    currentVersion: info.currentVersion,
    wantedVersion: info.wantedVersion,
    latestVersion: info.latestVersion,
    isMajorBump: info.isMajorBump,
    dependencyScope: info.dependencyScope,
  })) satisfies OutdatedPackage[];
}
