import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { type PackageManager } from "../../../infra/package-manager/index.js";
import { withRepoLock } from "../../../infra/repo-lock.js";
import { errorMessage } from "../../../shared/errors.js";
import { safeExecaCommand } from "../../../shared/exec/safe-exec-command.js";
import { LONG_RUNNING_TIMEOUT_MS } from "../../../shared/timeouts.js";

/** Rewrites one dependency's range in package.json, reinstalls, optionally tests, and reverts on failure. */
// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface RawPackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  [key: string]: unknown;
}

type DepField = "dependencies" | "devDependencies" | "peerDependencies";

export interface BumpResult {
  applied: boolean;
  message: string;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

export async function applyBump(params: {
  cwd: string;
  packageName: string;
  fromVersion: string;
  toVersion: string;
  pm: PackageManager;
  installCommand: string[];
  testCommand: string[];
  runTests: boolean;
}): Promise<BumpResult> {
  const target = readBumpTarget(params.cwd, params.packageName, params.toVersion);
  if ("failure" in target) return target.failure;
  const { pkgPath, pkgJson, depField, currentRange, newRange } = target;

  return withRepoLock(params.cwd, async () => {
    pkgJson[depField]![params.packageName] = newRange;
    writeFileSync(pkgPath, JSON.stringify(pkgJson, null, 2) + "\n", "utf8");

    try {
      await safeExecaCommand(params.installCommand, {
        timeoutMs: LONG_RUNNING_TIMEOUT_MS,
        cwd: params.cwd,
        stdio: "pipe",
      });
    } catch (err) {
      pkgJson[depField]![params.packageName] = currentRange;
      writeFileSync(pkgPath, JSON.stringify(pkgJson, null, 2) + "\n", "utf8");
      const message = errorMessage(err);
      return {
        applied: false,
        message: `${params.installCommand.join(" ")} failed after updating "${params.packageName}" to ${params.toVersion}. Reverted. Error: ${message}`,
      };
    }

    if (params.runTests) {
      try {
        await safeExecaCommand(params.testCommand, {
          timeoutMs: LONG_RUNNING_TIMEOUT_MS,
          cwd: params.cwd,
          stdio: "pipe",
        });
      } catch (err) {
        pkgJson[depField]![params.packageName] = currentRange;
        writeFileSync(pkgPath, JSON.stringify(pkgJson, null, 2) + "\n", "utf8");
        try {
          await safeExecaCommand(params.installCommand, {
            timeoutMs: LONG_RUNNING_TIMEOUT_MS,
            cwd: params.cwd,
            stdio: "pipe",
          });
        } catch {
          // Ignore rollback install failure.
        }
        const message = errorMessage(err);
        return {
          applied: false,
          message: `Tests failed after upgrading "${params.packageName}" to ${params.toVersion}. Rolled back. Error: ${message}`,
        };
      }
    }

    return {
      applied: true,
      message: `Updated ${params.packageName} from ${params.fromVersion} to ${params.toVersion}.`,
    };
  });
}

type BumpTarget =
  | {
      pkgPath: string;
      pkgJson: RawPackageJson;
      depField: DepField;
      currentRange: string;
      newRange: string;
    }
  | { failure: BumpResult };

/** The manifest, the field the package is declared in and the range it will get. */
function readBumpTarget(cwd: string, packageName: string, toVersion: string): BumpTarget {
  const pkgPath = join(cwd, "package.json");

  let pkgJson: RawPackageJson;
  try {
    pkgJson = JSON.parse(readFileSync(pkgPath, "utf8")) as RawPackageJson;
  } catch {
    return { failure: { applied: false, message: `Could not read package.json at "${pkgPath}".` } };
  }

  const depField = (["dependencies", "devDependencies", "peerDependencies"] as DepField[]).find(
    (f) => pkgJson[f]?.[packageName] !== undefined,
  );
  if (!depField) {
    return {
      failure: {
        applied: false,
        message: `"${packageName}" was not found in package.json dependencies.`,
      },
    };
  }

  const currentRange = pkgJson[depField]![packageName]!;
  const prefix = /^([~^]?)/.exec(currentRange)?.[1] ?? "";
  return { pkgPath, pkgJson, depField, currentRange, newRange: `${prefix}${toVersion}` };
}
