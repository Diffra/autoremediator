/**
 * Outdated-package detection: runs the package manager's `outdated --json` command in a project
 * and turns its output (npm, pnpm or yarn v1 format) into one shape.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import semver from "semver";

import { type PackageManager, detectPackageManager } from "../../../infra/package-manager/index.js";
import { safeExeca } from "../../../shared/exec/safe-exec.js";

export interface NpmRegistryPackageInfo {
  /** The version currently installed in node_modules */
  currentVersion: string;
  /** Latest version satisfying the declared semver range */
  wantedVersion: string;
  /** Absolute latest version published on the registry */
  latestVersion: string;
  /** True when latestVersion crosses a major boundary from currentVersion */
  isMajorBump: boolean;
  /** "direct" if listed in root package.json; "transitive" otherwise */
  dependencyScope: "direct" | "transitive";
}

interface NpmOutdatedEntry {
  current?: string;
  wanted?: string;
  latest?: string;
  type?: string;
}

/**
 * Reads package.json at cwd, resolves all deps against npm registry via the
 * package-manager's outdated command, and returns info keyed by package name.
 *
 * If `includeTransitive` is false (default), only direct dependencies are returned.
 * Private/unavailable packages are skipped silently.
 * Registry unavailability throws with a descriptive message.
 */
export async function queryOutdatedPackages(
  cwd: string,
  options: { includeTransitive?: boolean; packageManager?: string } = {},
): Promise<Map<string, NpmRegistryPackageInfo>> {
  const pm = (options.packageManager ?? detectPackageManager(cwd)) as PackageManager;

  const stdout = await runOutdatedCommand(pm, cwd);
  if (!stdout.trim()) {
    return new Map();
  }

  const rawEntries = pm === "yarn" ? parseYarnOutdated(stdout) : parseNpmOutdated(stdout, pm);
  return toPackageInfoMap(rawEntries, readDirectDependencies(cwd), options.includeTransitive);
}

async function runOutdatedCommand(pm: PackageManager, cwd: string): Promise<string> {
  try {
    // npm, pnpm and yarn v1 all take --json for machine-readable output.
    // These commands exit with code 1 when outdated packages exist — that is expected.
    const result = await safeExeca(pm, ["outdated", "--json"], {
      cwd,
      reject: false,
      stdio: "pipe",
    });

    // Exit code 0 = no outdated packages; 1 = outdated packages (expected).
    // Any other code or no stdout on a non-zero exit = real failure.
    if (result.exitCode !== 0 && result.exitCode !== 1) {
      const stderr = typeof result.stderr === "string" ? result.stderr : "";
      if (!result.stdout) {
        throw new Error(
          `${pm} outdated --json failed (exit ${result.exitCode}): ${stderr.slice(0, 500)}`,
        );
      }
    }
    return typeof result.stdout === "string" ? result.stdout : "";
  } catch (err) {
    if (err instanceof Error && !err.message.includes("outdated --json failed")) {
      throw new Error(`Failed to query outdated packages: ${err.message}`, { cause: err });
    }
    throw err;
  }
}

/** yarn v1 emits newline-delimited JSON objects; the outdated list is the `table` object. */
function parseYarnOutdated(stdout: string): Record<string, NpmOutdatedEntry> {
  const rawEntries: Record<string, NpmOutdatedEntry> = {};
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed) as { type?: string; data?: unknown };
      if (parsed.type === "table" && parsed.data) {
        addYarnTable(rawEntries, parsed.data);
      }
    } catch {
      // Skip unparseable lines
    }
  }
  return rawEntries;
}

function addYarnTable(
  rawEntries: Record<string, NpmOutdatedEntry>,
  tableData: { head?: string[]; body?: string[][] },
): void {
  const head = tableData.head ?? [];
  const currentIdx = head.indexOf("Current");
  const wantedIdx = head.indexOf("Wanted");
  const latestIdx = head.indexOf("Latest");
  for (const row of tableData.body ?? []) {
    const name = row[0];
    if (!name) continue;
    rawEntries[name] = {
      current: row[currentIdx] ?? "",
      wanted: row[wantedIdx] ?? "",
      latest: row[latestIdx] ?? "",
      type: row[head.indexOf("Package Type")] ?? "dependencies",
    };
  }
}

/**
 * npm: { "packageName": { current, wanted, latest, type } }
 * pnpm v7+: may be an array — handled as best effort.
 */
function parseNpmOutdated(stdout: string, pm: PackageManager): Record<string, NpmOutdatedEntry> {
  const rawEntries: Record<string, NpmOutdatedEntry> = {};
  try {
    const parsed = JSON.parse(stdout);
    if (Array.isArray(parsed)) {
      // pnpm v7+ array format: [{ name, current, wanted, latest, dependencyType }]
      for (const entry of parsed as Array<{
        name?: string;
        packageName?: string;
        current?: string;
        wanted?: string;
        latest?: string;
        dependencyType?: string;
      }>) {
        const name = entry.name ?? entry.packageName;
        if (!name) continue;
        rawEntries[name] = {
          current: entry.current,
          wanted: entry.wanted,
          latest: entry.latest,
          type: entry.dependencyType,
        };
      }
    } else {
      // npm standard object format
      Object.assign(rawEntries, parsed as Record<string, NpmOutdatedEntry>);
    }
  } catch {
    throw new Error(`Could not parse ${pm} outdated --json output.`);
  }
  return rawEntries;
}

/** Names listed in the project's own package.json; empty when it cannot be read. */
function readDirectDependencies(cwd: string): Set<string> {
  try {
    const pkgRaw = JSON.parse(readFileSync(join(cwd, "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    return new Set([
      ...Object.keys(pkgRaw.dependencies ?? {}),
      ...Object.keys(pkgRaw.devDependencies ?? {}),
    ]);
  } catch {
    return new Set();
  }
}

function toPackageInfoMap(
  rawEntries: Record<string, NpmOutdatedEntry>,
  directDeps: Set<string>,
  includeTransitive: boolean | undefined,
): Map<string, NpmRegistryPackageInfo> {
  const result = new Map<string, NpmRegistryPackageInfo>();

  for (const [name, entry] of Object.entries(rawEntries)) {
    const currentVersion = entry.current ?? "";
    const wantedVersion = entry.wanted ?? currentVersion;
    const latestVersion = entry.latest ?? currentVersion;

    if (!currentVersion || !latestVersion) continue;

    const dependencyScope: "direct" | "transitive" = directDeps.has(name) ? "direct" : "transitive";

    // Skip transitive if not requested
    if (!includeTransitive && dependencyScope === "transitive") continue;

    const isMajorBump =
      semver.valid(currentVersion) !== null &&
      semver.valid(latestVersion) !== null &&
      semver.major(latestVersion) > semver.major(currentVersion);

    result.set(name, {
      currentVersion,
      wantedVersion,
      latestVersion,
      isMajorBump,
      dependencyScope,
    });
  }

  return result;
}
