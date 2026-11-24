/**
 * npm registry API client
 *
 * Used to:
 * - Fetch the full list of published versions for a package
 * - Find the lowest semver-compatible safe upgrade from `firstPatchedVersion`
 * - Download tarballs for patch generation (fallback path)
 * - Query installed packages for outdated version information via the package manager
 *   (see `outdated-packages.ts`; tarball download and checks are in `tarball.ts`)
 *
 * Uses shared HTTP client for consistent error handling and timeouts.
 */
import semver from "semver";

import { httpClient } from "../../../infra/http/http-client.js";
import {
  type RegistryConfig,
  defaultRegistryConfig,
  packumentUrl,
} from "../../../infra/http/registry-config.js";

export type { NpmRegistryPackageInfo } from "./outdated-packages.js";
export { queryOutdatedPackages } from "./outdated-packages.js";
export type { TarballInfo } from "./tarball.js";
export {
  assertTarballUrlAllowed,
  downloadTarball,
  getTarballInfo,
  verifyTarballIntegrity,
} from "./tarball.js";

export type SafeUpgradeLevel = "patch" | "minor" | "major";

export interface SafeUpgradeResolution {
  safeVersion?: string;
  upgradeLevel?: SafeUpgradeLevel;
  candidates: Partial<Record<SafeUpgradeLevel, string>>;
  majorOnlyFixAvailable: boolean;
  /**
   * Every acceptable fixed version, best first: smallest upgrade level, then lowest version,
   * with deprecated releases last. Callers that reject `safeVersion` can try the next one.
   */
  ordered: string[];
}

// ---------------------------------------------------------------------------
// Raw registry types (abbreviated)
// ---------------------------------------------------------------------------

interface NpmPackument {
  name: string;
  versions: Record<string, { version: string; deprecated?: string; dist: { tarball: string } }>;
  "dist-tags": Record<string, string>;
  time: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface PackageVersionInfo {
  versions: string[];
  /** Versions the maintainers have marked deprecated. */
  deprecated: Set<string>;
}

/**
 * Fetch all published versions for an npm package, noting which are deprecated.
 * Returns empty info if the package is not found or the registry is unreachable.
 */
export async function fetchPackageVersionInfo(
  packageName: string,
  registry: RegistryConfig = defaultRegistryConfig,
): Promise<PackageVersionInfo> {
  const url = packumentUrl(registry, packageName);

  try {
    const res = await httpClient({ url, headers: registry.headersFor(url) });

    if (res.status === 404) return { versions: [], deprecated: new Set() };
    if (!res.ok) {
      throw new Error(`npm registry error ${res.status} for "${packageName}": ${res.text}`);
    }

    const data = res.data as NpmPackument;
    const versions = Object.keys(data.versions);
    const deprecated = new Set(
      versions.filter((version) => Boolean(data.versions[version]?.deprecated)),
    );
    return { versions, deprecated };
  } catch (err) {
    // If httpClient throws (timeout, network error), treat as not found
    if (err instanceof Error && err.message.includes("registry error")) {
      throw err;
    }
    return { versions: [], deprecated: new Set() };
  }
}

/**
 * Fetch all published versions for an npm package.
 * Returns an empty array if the package is not found.
 */
export async function fetchPackageVersions(
  packageName: string,
  registry: RegistryConfig = defaultRegistryConfig,
): Promise<string[]> {
  return (await fetchPackageVersionInfo(packageName, registry)).versions;
}

/**
 * Find the lowest published version that satisfies `>= firstPatchedVersion`
 * and is semver-compatible with the currently installed version (same major,
 * unless there is no same-major option).
 *
 * Strategy:
 *   1. Try same-major, lowest version >= firstPatchedVersion
 *   2. Fallback: any published version >= firstPatchedVersion (lowest)
 *   3. Returns undefined if nothing found
 */
export async function findSafeUpgradeVersion(
  packageName: string,
  installedVersion: string,
  firstPatchedVersion: string,
  vulnerableRange?: string,
  registry?: RegistryConfig,
): Promise<string | undefined> {
  const resolution = await resolveSafeUpgradeVersion(
    packageName,
    installedVersion,
    firstPatchedVersion,
    vulnerableRange,
    registry,
  );

  return resolution.safeVersion;
}

export async function resolveSafeUpgradeVersion(
  packageName: string,
  installedVersion: string,
  firstPatchedVersion: string,
  vulnerableRange?: string,
  registry?: RegistryConfig,
): Promise<SafeUpgradeResolution> {
  const { versions, deprecated } = await fetchPackageVersionInfo(packageName, registry);
  const none: SafeUpgradeResolution = {
    candidates: {},
    majorOnlyFixAvailable: false,
    ordered: [],
  };
  if (!versions.length) return none;

  // Prereleases are only acceptable when the project is already on one or the advisory's fix is one.
  const allowPrerelease =
    Boolean(semver.prerelease(installedVersion)) || Boolean(semver.prerelease(firstPatchedVersion));

  // All fixed versions >= firstPatchedVersion that are not themselves in the vulnerable range
  const fixed = versions
    .filter((v) => semver.valid(v) && semver.gte(v, firstPatchedVersion))
    .filter((v) => allowPrerelease || !semver.prerelease(v))
    .filter((v) => {
      if (!vulnerableRange) return true;
      try {
        return !semver.satisfies(v, vulnerableRange, { includePrerelease: false });
      } catch {
        // If vulnerable range cannot be parsed, avoid filtering out candidates.
        return true;
      }
    })
    .toSorted(semver.compare);

  if (!fixed.length) return none;

  // Deprecated releases are a last resort: they often still carry the fix, but maintainers
  // advise against them.
  const preferred = fixed.filter((v) => !deprecated.has(v));
  const pool = preferred.length > 0 ? preferred : fixed;

  const categorizedCandidates: SafeUpgradeResolution["candidates"] = {};
  const levelRank: Record<SafeUpgradeLevel, number> = { patch: 0, minor: 1, major: 2 };
  const ranked: Array<{ version: string; rank: number }> = [];

  for (const candidate of pool) {
    const level = classifyUpgradeLevel(installedVersion, candidate);
    if (!level) continue;
    ranked.push({ version: candidate, rank: levelRank[level] });
    if (!categorizedCandidates[level]) {
      categorizedCandidates[level] = candidate;
    }
  }

  // `pool` is ascending by version, and the sort is stable, so equal ranks stay ascending.
  const ordered = [
    ...ranked.toSorted((a, b) => a.rank - b.rank).map((entry) => entry.version),
    ...(pool === fixed ? [] : fixed.filter((v) => deprecated.has(v))),
  ];

  const safeVersion = ordered[0];
  if (!safeVersion) {
    return { candidates: categorizedCandidates, majorOnlyFixAvailable: false, ordered };
  }

  return {
    safeVersion,
    upgradeLevel: classifyUpgradeLevel(installedVersion, safeVersion),
    candidates: categorizedCandidates,
    majorOnlyFixAvailable:
      !categorizedCandidates.patch &&
      !categorizedCandidates.minor &&
      Boolean(categorizedCandidates.major),
    ordered,
  };
}

export function classifyUpgradeLevel(
  installedVersion: string,
  candidateVersion: string,
): SafeUpgradeLevel | undefined {
  const installed = semver.parse(installedVersion) ?? semver.coerce(installedVersion);
  const candidate = semver.parse(candidateVersion) ?? semver.coerce(candidateVersion);

  if (!installed || !candidate) return undefined;
  if (!semver.gte(candidate.version, installed.version)) return undefined;

  if (candidate.major > installed.major) return "major";
  if (candidate.major === installed.major && candidate.minor > installed.minor) return "minor";
  if (
    candidate.major === installed.major &&
    candidate.minor === installed.minor &&
    candidate.patch >= installed.patch
  ) {
    return "patch";
  }

  return undefined;
}

// ---------------------------------------------------------------------------
// Release timeline (freshness)
// ---------------------------------------------------------------------------

export interface PackageTimeline {
  /** Every published version, in the registry's order. */
  versions: string[];
  /** Versions the maintainers have marked deprecated. */
  deprecated: Set<string>;
  /** Publish time of each version (ISO date), where the registry gives one. */
  published: Map<string, string>;
}

/**
 * The published versions of a package with when each was published, from its packument's `time`.
 * Returns undefined when the package is not on the registry. Throws on a registry error, so a
 * caller can tell "does not exist" from "could not be read".
 */
export async function fetchPackageTimeline(
  packageName: string,
  registry: RegistryConfig = defaultRegistryConfig,
): Promise<PackageTimeline | undefined> {
  const url = packumentUrl(registry, packageName);
  const res = await httpClient({ url, headers: registry.headersFor(url) });
  if (res.status === 404) return undefined;
  if (!res.ok) {
    throw new Error(`npm registry error ${res.status} for "${packageName}": ${res.text}`);
  }
  const data = res.data as Partial<NpmPackument>;
  const versions = Object.keys(data.versions ?? {});
  const published = new Map<string, string>();
  for (const version of versions) {
    const at = data.time?.[version];
    if (typeof at === "string" && !Number.isNaN(Date.parse(at))) published.set(version, at);
  }
  return {
    versions,
    deprecated: new Set(
      versions.filter((version) => Boolean(data.versions?.[version]?.deprecated)),
    ),
    published,
  };
}
