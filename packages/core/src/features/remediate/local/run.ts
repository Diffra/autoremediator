import { loadPolicy } from "../../../infra/policy/policy.js";
import { createProjectSnapshot } from "../../../infra/rollback/rollback.js";
import type { CveDetails, VulnerablePackage } from "../../intelligence/types.js";
import { loadMemoryConstraints } from "../../memory/consume.js";
import type { PatchGenerator } from "../../patch/patch-generator.js";
import { resolvePatchGenerator } from "../../patch/resolve.js";
import { checkInventoryTool } from "../tools/check-inventory.js";
import type {
  LlmUsageMetrics,
  PatchResult,
  RemediateOptions,
  RemediationReport,
} from "../types.js";
import { lookupCveDetails } from "./cve-lookup.js";
import { resolveLocalRunOptions, type LocalRunOptions } from "./options.js";
import { type PackageRunContext, remediateVulnerable } from "./package-remediation.js";
import { buildSbom, sbomKey } from "./sbom.js";
import { runSecOpsPreflight, type SecOpsPreflightResult } from "./secops-preflight.js";
import { buildLocalSummary } from "./summary.js";
import { findVulnerablePackages } from "./vulnerability-match.js";

type Correlation = NonNullable<RemediationReport["correlation"]>;

/** The report for a CVE a VEX suppression covers: nothing is modified, but VEX and SBOM still show it. */
async function suppressedReport(
  cveId: string,
  cveDetails: CveDetails,
  suppression: Extract<SecOpsPreflightResult, { suppressed: true }>,
  run: { options: RemediateOptions; resolved: LocalRunOptions; correlation: Correlation },
): Promise<RemediationReport> {
  const { options, resolved, correlation } = run;
  // The report still names the installed copies the CVE covers, so VEX can assert not_affected.
  const inventory =
    cveDetails.affectedPackages.length > 0
      ? await checkInventoryTool.execute({
          cwd: resolved.cwd,
          packageManager: resolved.packageManager,
          policy: options.policy,
          workspace: resolved.constraints.workspace,
        })
      : { packages: [] };
  const installed = inventory.error ? [] : inventory.packages;
  const packages = findVulnerablePackages(cveDetails, installed);
  const suppressedBy = {
    justification: suppression.suppression.justification,
    ...(suppression.suppression.notes ? { notes: suppression.suppression.notes } : {}),
  };
  const results: PatchResult[] = packages.map((vulnerable) => ({
    packageName: vulnerable.installed.name,
    fromVersion: vulnerable.installed.version,
    strategy: "none",
    applied: false,
    dryRun: resolved.dryRun,
    dependencyScope: vulnerable.installed.type === "direct" ? "direct" : "transitive",
    suppressedBy,
    message: suppression.summary,
  }));
  return {
    cveId,
    cveDetails,
    vulnerablePackages: packages,
    results,
    summary: suppression.summary,
    sbom: buildSbom(
      installed,
      new Set(packages.map((v) => sbomKey(v.installed.name, v.installed.version))),
      results,
    ),
    correlation,
  };
}

export async function runLocalRemediationPipeline(
  cveId: string,
  options: RemediateOptions = {},
): Promise<RemediationReport> {
  const resolved = resolveLocalRunOptions(options);
  const { cwd, packageManager, constraints } = resolved;
  const correlation: Correlation = {
    requestId: options.requestId,
    sessionId: options.sessionId,
    parentRunId: options.parentRunId,
  };
  const normalizedId = cveId.toUpperCase();
  const unresolved = (
    summary: string,
    cveDetails: CveDetails | null,
    extra: Partial<RemediationReport> = {},
  ): RemediationReport => ({
    cveId,
    cveDetails,
    vulnerablePackages: [],
    results: [],
    summary,
    ...extra,
    correlation,
  });

  const cveDetails = await lookupCveDetails(normalizedId, resolved);
  if (!cveDetails) {
    return unresolved(
      resolved.offlineIntelligence
        ? `Offline mode: ${normalizedId} not found in intelligence snapshot.`
        : `Local mode failed at lookup-cve: ${normalizedId} not found in OSV or GitHub advisory data.`,
      null,
    );
  }

  const preflight = await runSecOpsPreflight(normalizedId, cveDetails, resolved);
  if (preflight.suppressed) {
    return suppressedReport(cveId, cveDetails, preflight, { options, resolved, correlation });
  }
  const { exploitSignalTriggered, slaBreaches } = preflight;
  const signals = { exploitSignalTriggered, slaBreaches };

  if (cveDetails.affectedPackages.length === 0) {
    return unresolved(
      `Local mode lookup succeeded but no npm affected packages were found for ${normalizedId}.`,
      cveDetails,
      signals,
    );
  }

  const inventory = await checkInventoryTool.execute({
    cwd,
    packageManager,
    policy: options.policy,
    workspace: constraints.workspace,
  });
  if (inventory?.error) {
    return unresolved(
      `Local mode failed at check-inventory: ${inventory.error}`,
      cveDetails,
      signals,
    );
  }
  const installedPackages = inventory.packages ?? [];
  const vulnerablePackages = findVulnerablePackages(cveDetails, installedPackages);

  const context = createRunContext(normalizedId, cveDetails, { options, resolved, signals });
  const { results, llmUsage } = await remediateAll(context, vulnerablePackages);

  return buildReport(
    { cveId, cveDetails, vulnerablePackages, installedPackages, results },
    {
      llmUsage,
      signals,
      correlation,
    },
  );
}

function createRunContext(
  cveId: string,
  cveDetails: CveDetails,
  run: {
    options: RemediateOptions;
    resolved: LocalRunOptions;
    signals: PackageRunContext["preflight"];
  },
): PackageRunContext {
  const { options, resolved, signals } = run;
  let generatorPromise: Promise<PatchGenerator | undefined> | undefined;
  return {
    cveId,
    cveDetails,
    options,
    resolved,
    policy: loadPolicy(resolved.cwd, options.policy),
    // What earlier runs and people recorded: pinned packages and upgrades tried and rejected.
    memory: resolved.ignoreMemory ? undefined : loadMemoryConstraints(resolved.cwd),
    preflight: signals,
    getGenerator: () =>
      (generatorPromise ??= resolvePatchGenerator({
        patchGenerator: options.patchGenerator,
        model: resolved.model,
      })),
  };
}

async function remediateAll(context: PackageRunContext, vulnerablePackages: VulnerablePackage[]) {
  const results: PatchResult[] = [];
  const llmUsage: LlmUsageMetrics[] = [];
  for (const vulnerable of vulnerablePackages) {
    const snapshot = await createProjectSnapshot(context.resolved.cwd);
    const outcome = await remediateVulnerable(context, vulnerable, snapshot);
    results.push(outcome.result);
    if (outcome.usage) llmUsage.push(...outcome.usage);
  }
  return { results, llmUsage };
}

function buildReport(
  found: {
    cveId: string;
    cveDetails: CveDetails;
    vulnerablePackages: VulnerablePackage[];
    installedPackages: Array<{ name: string; version: string; type: "direct" | "transitive" }>;
    results: PatchResult[];
  },
  extra: {
    llmUsage: LlmUsageMetrics[];
    signals: { exploitSignalTriggered?: boolean; slaBreaches?: RemediationReport["slaBreaches"] };
    correlation: Correlation;
  },
): RemediationReport {
  const { vulnerablePackages, results } = found;
  const vulnerableKeys = new Set(
    vulnerablePackages.map((v) => sbomKey(v.installed.name, v.installed.version)),
  );
  return {
    cveId: found.cveId,
    cveDetails: found.cveDetails,
    vulnerablePackages,
    results,
    summary: buildLocalSummary(vulnerablePackages, results),
    llmUsage: extra.llmUsage.length > 0 ? extra.llmUsage : undefined,
    ...extra.signals,
    sbom: buildSbom(found.installedPackages, vulnerableKeys, results),
    correlation: extra.correlation,
  };
}
