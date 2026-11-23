import semver from "semver";

import { DataFormatError, errorMessage } from "../../shared/errors.js";
import { parsePnpmLockDocument } from "./pnpm-lock-document.js";
import type { DeltaDependencyChange } from "./types.js";

type AddDependency = (name: string, version?: string) => void;

/**
 * Extracts a map of package names to their resolved versions from a lockfile content. A lockfile
 * that cannot be read is an error: reading it as "no dependencies" would make every package look
 * added or removed.
 */
export function parseLockfileDependencies(
  filename: string,
  content: string,
): Map<string, Set<string>> {
  const result = new Map<string, Set<string>>();

  const add: AddDependency = (name, ver) => {
    if (!name || !ver) return;
    const cleanVer = semver.clean(ver) || semver.coerce(ver)?.version || ver;
    let set = result.get(name);
    if (!set) {
      set = new Set();
      result.set(name, set);
    }
    set.add(cleanVer);
  };

  if (filename.endsWith("package-lock.json")) {
    readNpmLock(filename, content, add);
  } else if (filename.endsWith("pnpm-lock.yaml")) {
    readPnpmLock(filename, content, add);
  } else if (filename.endsWith("yarn.lock")) {
    readYarnLock(content, add);
  }

  return result;
}

function readNpmLock(filename: string, content: string, add: AddDependency): void {
  let data: {
    packages?: Record<string, unknown>;
    dependencies?: Record<string, unknown>;
  };
  try {
    data = JSON.parse(content);
  } catch (error) {
    throw new DataFormatError(`${filename} is not valid JSON: ${errorMessage(error)}`, {
      cause: error,
    });
  }
  if (data.packages && typeof data.packages === "object") {
    for (const [key, pkg] of Object.entries(data.packages)) {
      if (!key || key === "" || typeof pkg !== "object" || !pkg) continue;
      const idx = key.lastIndexOf("node_modules/");
      if (idx !== -1) {
        const rawName = key.slice(idx + "node_modules/".length);
        add(rawName, (pkg as { version?: string }).version);
      }
    }
  }
  if (data.dependencies && typeof data.dependencies === "object") {
    walkNestedDependencies(data.dependencies, add);
  }
}

function walkNestedDependencies(deps: Record<string, unknown>, add: AddDependency): void {
  for (const [name, info] of Object.entries(deps)) {
    if (!info || typeof info !== "object") continue;
    const depObj = info as { version?: string; dependencies?: Record<string, unknown> };
    add(name, depObj.version);
    if (depObj.dependencies && typeof depObj.dependencies === "object") {
      walkNestedDependencies(depObj.dependencies, add);
    }
  }
}

/** `/name@1.0.0(peer@2.0.0)` or `name@1.0.0` as `[name, version]`, or undefined when it has no version. */
function splitPnpmKey(key: string): [string, string] | undefined {
  let rawKey = key.replace(/^\//, "");
  const parenIdx = rawKey.indexOf("(");
  if (parenIdx !== -1) {
    rawKey = rawKey.slice(0, parenIdx);
  }
  const lastAt = rawKey.lastIndexOf("@");
  return lastAt > 0 ? [rawKey.slice(0, lastAt), rawKey.slice(lastAt + 1)] : undefined;
}

function readPnpmLock(filename: string, content: string, add: AddDependency): void {
  const parsed = parsePnpmLockDocument(content);
  // The shared reader skips documents that do not parse, so "nothing came back" means damaged.
  if (parsed === null || typeof parsed !== "object") {
    throw new DataFormatError(`${filename} is not a readable pnpm lockfile (invalid YAML?)`);
  }
  const data = parsed as {
    packages?: Record<string, { name?: string; version?: string }>;
    snapshots?: Record<string, unknown>;
  };
  if (data.packages && typeof data.packages === "object") {
    for (const [key, val] of Object.entries(data.packages)) {
      const parts = splitPnpmKey(key);
      if (parts) {
        add(val?.name ?? parts[0], val?.version ?? parts[1]);
      }
    }
  }
  if (data.snapshots && typeof data.snapshots === "object") {
    for (const key of Object.keys(data.snapshots)) {
      const parts = splitPnpmKey(key);
      if (parts) {
        add(parts[0], parts[1]);
      }
    }
  }
}

function readYarnLock(content: string, add: AddDependency): void {
  let currentPackages: string[] = [];
  for (const line of content.split("\n")) {
    if (line.startsWith("#") || line.trim() === "") continue;
    if (!line.startsWith(" ")) {
      currentPackages = [];
      const parts = line.split(",").map((p) => p.trim().replace(/^"/, "").replace(/":?$/, ""));
      for (const part of parts) {
        const lastAt = part.lastIndexOf("@");
        if (lastAt > 0) {
          currentPackages.push(part.slice(0, lastAt));
        }
      }
    } else {
      const match = /^\s+version\s+"?([^"\s]+)"?/.exec(line);
      if (match && currentPackages.length > 0) {
        for (const pkg of currentPackages) {
          add(pkg, match[1]);
        }
        currentPackages = [];
      }
    }
  }
}

/**
 * Computes difference between old and new lockfile content.
 */
export function computeLockfileDiff(
  filename: string,
  oldContent: string | null,
  newContent: string | null,
): DeltaDependencyChange[] {
  const changes: DeltaDependencyChange[] = [];
  const oldDeps = oldContent
    ? parseLockfileDependencies(filename, oldContent)
    : new Map<string, Set<string>>();
  const newDeps = newContent
    ? parseLockfileDependencies(filename, newContent)
    : new Map<string, Set<string>>();

  const allPkgs = new Set([...oldDeps.keys(), ...newDeps.keys()]);

  for (const pkg of allPkgs) {
    const oldVers = oldDeps.get(pkg) ?? new Set();
    const newVers = newDeps.get(pkg) ?? new Set();

    // Check newly introduced versions
    for (const nVer of newVers) {
      if (!oldVers.has(nVer)) {
        if (oldVers.size === 0) {
          changes.push({
            packageName: pkg,
            changeType: "added",
            newVersion: nVer,
            dependencyType: "transitive",
            manifestPath: filename,
          });
        } else {
          const [firstOld = ""] = oldVers;
          const cleanOld = semver.clean(firstOld) || semver.coerce(firstOld)?.version;
          const cleanNew = semver.clean(nVer) || semver.coerce(nVer)?.version;
          const isUpgrade =
            cleanOld && cleanNew && semver.valid(cleanOld) && semver.valid(cleanNew)
              ? semver.gt(cleanNew, cleanOld)
              : true;

          changes.push({
            packageName: pkg,
            changeType: isUpgrade ? "upgraded" : "downgraded",
            oldVersion: firstOld,
            newVersion: nVer,
            dependencyType: "transitive",
            manifestPath: filename,
          });
        }
      }
    }

    // Check removed versions (only if package no longer exists in new lockfile)
    if (newVers.size === 0 && oldVers.size > 0) {
      for (const oVer of oldVers) {
        changes.push({
          packageName: pkg,
          changeType: "removed",
          oldVersion: oVer,
          dependencyType: "transitive",
          manifestPath: filename,
        });
      }
    }
  }

  return changes;
}
