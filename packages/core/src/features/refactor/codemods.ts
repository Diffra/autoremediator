/**
 * Built-in codemods for breaking-change upgrades.
 *
 * When a package upgrade breaks the consumer's type check, this rewrites the affected call sites
 * with a fixed set of AST-based codemods. It is deliberately not a general refactoring engine:
 * only the migrations listed below (currently `rimraf`, `uuid`, `glob` and `mkdirp`, plus
 * caller-supplied argument transforms) are supported, and anything else is reported as
 * "no codemod matched".
 */
import { readFileSync, writeFileSync } from "node:fs";

import { errorMessage } from "../../shared/errors.js";
import type { ArgumentTransformOptions } from "./argument-transforms.js";
import type { ConsumerCallSite } from "./call-site-finder.js";
import { transformFileContent } from "./file-transform.js";

export { transformCallArguments } from "./argument-transforms.js";
export type { ArgumentTransformOptions } from "./argument-transforms.js";
export { parseCompilerDiagnostics } from "./compiler-diagnostics.js";
export type { ParsedTsDiagnostic } from "./compiler-diagnostics.js";

export interface RefactorParams {
  cwd: string;
  packageName: string;
  fromVersion: string;
  toVersion: string;
  diagnosticError: string;
  callSites: ConsumerCallSite[];
  argumentTransforms?: ArgumentTransformOptions;
}

export interface RefactorExecutionResult {
  applied: boolean;
  refactoredFiles: string[];
  snapshots: Record<string, string>;
  error?: string;
}

/**
 * Restores original file contents from snapshot in case of failure.
 */
export function revertRefactorSnapshots(snapshots: Record<string, string>): void {
  for (const [filePath, content] of Object.entries(snapshots)) {
    try {
      writeFileSync(filePath, content, "utf8");
    } catch {
      // Ignore write errors during emergency rollback
    }
  }
}

export async function refactorConsumerCallSites(
  params: RefactorParams,
): Promise<RefactorExecutionResult> {
  const { packageName, diagnosticError, callSites, argumentTransforms } = params;

  if (callSites.length === 0) {
    return {
      applied: false,
      refactoredFiles: [],
      snapshots: {},
      error: `No consumer call sites found for "${packageName}".`,
    };
  }

  const snapshots: Record<string, string> = {};
  const refactoredFiles: string[] = [];

  try {
    for (const site of callSites) {
      const originalContent = site.sourceContent || readFileSync(site.filePath, "utf8");
      snapshots[site.filePath] = originalContent;

      const { modified, newContent } = transformFileContent(
        originalContent,
        packageName,
        diagnosticError,
        site.filePath,
        argumentTransforms,
      );

      if (modified && newContent !== originalContent) {
        writeFileSync(site.filePath, newContent, "utf8");
        refactoredFiles.push(site.filePath);
      }
    }

    if (refactoredFiles.length === 0) {
      return {
        applied: false,
        refactoredFiles: [],
        snapshots,
        error: "No automated codemod pattern matched the diagnostic error.",
      };
    }

    return {
      applied: true,
      refactoredFiles,
      snapshots,
    };
  } catch (err) {
    revertRefactorSnapshots(snapshots);
    const message = errorMessage(err);
    return {
      applied: false,
      refactoredFiles: [],
      snapshots,
      error: `Failed to apply breaking change refactoring: ${message}`,
    };
  }
}
