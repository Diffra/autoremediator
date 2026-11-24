/**
 * Package pre-installation security evaluator
 *
 * Used to evaluate security posture of an npm package before installing or updating it.
 * Queries OSV for known vulnerabilities, enriches with EPSS and CISA KEV exploit telemetry,
 * and recommends safe upgrade targets.
 */
import semver from "semver";

import { loadRegistryConfig } from "../../infra/http/registry-config.js";
import { UpstreamError, errorMessage } from "../../shared/errors.js";
import { assertValidPackageName } from "../../shared/package-name.js";
import { fetchCisaKevFeed, findKevEntry } from "./sources/cisa-kev.js";
import { fetchEpss } from "./sources/epss.js";
import { queryOsvPackage, parseOsvVuln } from "./sources/osv.js";
import { fetchPackageVersions, findSafeUpgradeVersion } from "./sources/registry.js";
import type {
  EvaluatePackageOptions,
  PackageEvaluationReport,
  VulnerabilityEvaluationEntry,
} from "./types.js";

export async function evaluatePackage(
  packageName: string,
  options: EvaluatePackageOptions = {},
): Promise<PackageEvaluationReport> {
  assertValidPackageName(packageName);
  const version = options.version?.trim();
  const enrich = options.enrichIntelligence !== false;

  const registry = loadRegistryConfig(options.cwd);
  const latestVersion = await latestStableVersion(packageName, registry);

  const rawVulns = await queryAdvisories(packageName, version);

  const kevFeed = enrich ? await loadKevFeed() : null;

  const entries: VulnerabilityEvaluationEntry[] = [];

  for (const raw of rawVulns) {
    const entry = await evaluateAdvisory(raw, { packageName, version, enrich, kevFeed, registry });
    if (entry) entries.push(entry);
  }

  const isVulnerable = entries.length > 0;
  const verdict = verdictOf(entries);

  // Determine recommended safe version
  let recommendedVersion: string | undefined;
  if (isVulnerable) {
    const upgradeCandidates = entries
      .map((e) => e.safeUpgradeVersion)
      .filter((v): v is string => Boolean(v && semver.valid(v)))
      .toSorted((a, b) => semver.compare(a, b));

    recommendedVersion = upgradeCandidates.at(-1) || latestVersion;
  } else {
    recommendedVersion = version || latestVersion;
  }

  const summary = isVulnerable
    ? `Package "${packageName}${version ? `@${version}` : ""}" has ${entries.length} known vulnerability(ies) (verdict: ${verdict}). Recommended safe version: ${recommendedVersion || "none"}.`
    : `Package "${packageName}${version ? `@${version}` : ""}" has no known vulnerabilities. Safe to install.`;

  return {
    schemaVersion: "1.0",
    packageName,
    evaluatedVersion: version,
    isVulnerable,
    verdict,
    summary,
    vulnerabilities: entries,
    recommendedVersion,
    latestVersion,
    generatedAt: new Date().toISOString(),
  };
}

/**
 * The advisories OSV holds for the package. A failed lookup is an error, never an empty list:
 * "no advisories" and "could not ask" must not both read as safe.
 */
async function queryAdvisories(
  packageName: string,
  version: string | undefined,
): Promise<Awaited<ReturnType<typeof queryOsvPackage>>> {
  try {
    return await queryOsvPackage(packageName, version);
  } catch (error) {
    throw new UpstreamError(
      `Could not check OSV for known vulnerabilities in "${packageName}": ${errorMessage(error)}. The package was not judged.`,
      { cause: error },
    );
  }
}

type Registry = ReturnType<typeof loadRegistryConfig>;

/** The highest stable version the registry lists. A registry failure leaves it unknown; OSV still decides. */
async function latestStableVersion(
  packageName: string,
  registry: Registry,
): Promise<string | undefined> {
  try {
    const versions = await fetchPackageVersions(packageName, registry);
    return versions
      .filter((v) => semver.valid(v))
      .toSorted((a, b) => semver.compare(a, b))
      .at(-1);
  } catch {
    // Registry lookup failure shouldn't abort OSV checks
    return undefined;
  }
}

/** The CISA KEV feed, or null when it cannot be read: exploit enrichment is best effort. */
async function loadKevFeed(): Promise<Awaited<ReturnType<typeof fetchCisaKevFeed>> | null> {
  try {
    return await fetchCisaKevFeed();
  } catch {
    return null;
  }
}

interface AdvisoryContext {
  packageName: string;
  version: string | undefined;
  enrich: boolean;
  kevFeed: Awaited<ReturnType<typeof fetchCisaKevFeed>> | null;
  registry: Registry;
}

/** One OSV advisory as a report entry, or undefined when it does not touch the requested version. */
async function evaluateAdvisory(
  raw: Awaited<ReturnType<typeof queryOsvPackage>>[number],
  context: AdvisoryContext,
): Promise<VulnerabilityEvaluationEntry | undefined> {
  const { packageName, version, enrich, kevFeed, registry } = context;
  const cveDetails = parseOsvVuln(raw);
  const affected = cveDetails.affectedPackages.find(
    (p) => p.name.toLowerCase() === packageName.toLowerCase(),
  );

  // If a specific version was requested, verify semver matching
  if (version && affected?.vulnerableRange) {
    const cleanVer = semver.clean(version) || version;
    if (semver.valid(cleanVer) && !semver.satisfies(cleanVer, affected.vulnerableRange)) {
      return undefined;
    }
  }

  let inCisaKev = false;
  let epssScore: number | undefined;
  let epssPercentile: number | undefined;

  if (enrich && cveDetails.id.startsWith("CVE-")) {
    if (kevFeed) {
      inCisaKev = Boolean(findKevEntry(kevFeed, cveDetails.id));
    }
    try {
      const epss = await fetchEpss(cveDetails.id);
      if (epss) {
        epssScore = Number.parseFloat(epss.epss);
        epssPercentile = Number.parseFloat(epss.percentile);
      }
    } catch {
      // Soft fail on individual EPSS queries
    }
  }

  let safeUpgradeVersion: string | undefined;
  if (affected?.firstPatchedVersion) {
    try {
      const safe = await findSafeUpgradeVersion(
        packageName,
        version || "0.0.0",
        affected.firstPatchedVersion,
        undefined,
        registry,
      );
      safeUpgradeVersion = safe ?? affected.firstPatchedVersion;
    } catch {
      safeUpgradeVersion = affected.firstPatchedVersion;
    }
  }

  return {
    cveId: cveDetails.id,
    severity: cveDetails.severity,
    summary: cveDetails.summary,
    vulnerableRange: affected?.vulnerableRange,
    firstPatchedVersion: affected?.firstPatchedVersion,
    safeUpgradeVersion,
    epssScore,
    epssPercentile,
    inCisaKev,
    references: cveDetails.references,
  };
}

function verdictOf(
  entries: readonly VulnerabilityEvaluationEntry[],
): PackageEvaluationReport["verdict"] {
  if (entries.length === 0) {
    return "safe";
  }
  if (entries.some((e) => e.inCisaKev || (e.epssScore && e.epssScore > 0.5))) {
    return "actively-exploited";
  }
  const hasHighOrCritical = entries.some((e) => e.severity === "CRITICAL" || e.severity === "HIGH");
  return hasHighOrCritical ? "vulnerable" : "caution";
}
