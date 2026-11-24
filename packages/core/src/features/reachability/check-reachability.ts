/**
 * Tool: check-reachability (Pillar 3.1)
 *
 * Uses the high-performance Oxc (Oxidation Compiler) AST parser to scan project
 * source files for static imports, dynamic imports, CommonJS require calls,
 * and re-exports. Performs interprocedural AST call-graph tracing for target symbols
 * and resolves tsconfig/jsconfig path aliases.
 *
 * The scanning pieces live next to this file (`source-files.ts`, `tsconfig-paths.ts`,
 * `package-references.ts`, `symbol-invocations.ts`); this file combines them into a verdict.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { z } from "zod";

import { defineTool } from "../remediate/tools/tool-compat.js";
import { extractPackageReferences, type ExtractedReference } from "./package-references.js";
import { walkSourceFiles } from "./source-files.js";
import { traceSymbolInvocations } from "./symbol-invocations.js";
import { loadTsconfigPaths } from "./tsconfig-paths.js";
import type { ReachabilityAssessment, ReachabilityEvidence } from "./types.js";

export type { TsconfigPathsConfig } from "./tsconfig-paths.js";
export { loadTsconfigPaths, resolveAliasedPath } from "./tsconfig-paths.js";
export { walkSourceFiles } from "./source-files.js";
export type { ExtractedReference } from "./package-references.js";
export { extractPackageReferences, toRootPackageName } from "./package-references.js";
export { traceSymbolInvocations } from "./symbol-invocations.js";

export function findTransitiveDependencyPath(
  cwd: string,
  targetPackage: string,
  importedDirectPackages: Set<string>,
): { directDependency: string; version?: string } | null {
  for (const directPkg of importedDirectPackages) {
    const manifestPath = join(cwd, "node_modules", directPkg, "package.json");
    if (!existsSync(manifestPath)) continue;
    try {
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
        dependencies?: Record<string, string>;
      };
      if (manifest.dependencies?.[targetPackage]) {
        return {
          directDependency: directPkg,
          version: manifest.dependencies[targetPackage],
        };
      }
    } catch {
      // Ignore read errors
    }
  }
  return null;
}

export function assessPackageReachability(
  cwd: string,
  packageName: string,
  targetSymbol?: string,
): ReachabilityAssessment {
  return evaluateScan(scanForPackage(cwd, packageName), cwd, packageName, targetSymbol);
}

/**
 * Reachability of several symbols of one package. The project is read once and each symbol is
 * judged exactly as `assessPackageReachability` would judge it alone.
 */
export function assessSymbolsReachability(
  cwd: string,
  packageName: string,
  symbols: readonly string[],
): Map<string, ReachabilityAssessment> {
  const scan = scanForPackage(cwd, packageName);
  const results = new Map<string, ReachabilityAssessment>();
  for (const symbol of symbols) results.set(symbol, evaluateScan(scan, cwd, packageName, symbol));
  return results;
}

export const checkReachabilityTool = defineTool({
  description:
    "Scan project source files for import/require/export references and perform AST call-graph reachability analysis for a package and vulnerable symbols using Oxc AST parser. Returns reachability status: reachable, not-reachable, or unknown.",
  inputSchema: z.object({
    cwd: z.string().describe("Project root directory to scan"),
    packageName: z.string().describe("Package name to search for (e.g. 'lodash' or '@babel/core')"),
    symbol: z
      .string()
      .optional()
      .describe("Optional vulnerable function/symbol name to check specifically in call graph"),
  }),
  execute({ cwd, packageName, symbol }) {
    return assessPackageReachability(cwd, packageName, symbol);
  },
});

interface ScannedFile {
  filePath: string;
  content: string;
  refs: ExtractedReference[];
}

interface PackageScan {
  scanned: number;
  files: ScannedFile[];
  importedDirectPackages: Set<string>;
}

/** Read every project source file once and keep the ones that reference the package. */
function scanForPackage(cwd: string, packageName: string): PackageScan {
  const tsconfig = loadTsconfigPaths(cwd);
  const importedDirectPackages = new Set<string>();
  const files: ScannedFile[] = [];
  let scanned = 0;

  for (const filePath of walkSourceFiles(cwd)) {
    scanned++;
    let content: string;
    try {
      content = readFileSync(filePath, "utf8");
    } catch {
      continue;
    }
    const refs = extractPackageReferences(
      filePath,
      content,
      packageName,
      tsconfig,
      importedDirectPackages,
    );
    if (refs.length > 0) files.push({ filePath, content, refs });
  }
  return { scanned, files, importedDirectPackages };
}

interface CollectedEvidence {
  evidence: ReachabilityEvidence[];
  hasReExport: boolean;
  totalInvocations: number;
}

function evaluateScan(
  scan: PackageScan,
  cwd: string,
  packageName: string,
  targetSymbol?: string,
): ReachabilityAssessment {
  const { evidence, hasReExport, totalInvocations } = collectEvidence(scan, targetSymbol);

  if (scan.scanned === 0) {
    return {
      packageName,
      status: "unknown",
      reason: `No source files found under ${cwd}`,
      reachabilityBasis: "unknown",
    };
  }

  if (scan.files.length === 0) {
    return assessUnreferencedPackage(scan, cwd, packageName);
  }

  if (targetSymbol) {
    return assessTargetSymbol({
      packageName,
      targetSymbol,
      evidence,
      hasReExport,
      totalInvocations,
    });
  }

  return {
    packageName,
    status: "reachable",
    reason: `Found ${evidence.length} source file(s) referencing '${packageName}'`,
    reachabilityBasis: "import-present",
    evidence,
  };
}

/** One evidence entry per reference that could touch the target symbol. */
function collectEvidence(scan: PackageScan, targetSymbol?: string): CollectedEvidence {
  const evidence: ReachabilityEvidence[] = [];
  let hasReExport = false;
  let totalInvocations = 0;

  for (const { filePath, content, refs } of scan.files) {
    for (const ref of refs) {
      if (ref.isReExported) {
        hasReExport = true;
      }

      const matchesSymbol =
        !targetSymbol ||
        ref.symbols.includes("*") ||
        ref.symbols.includes("default") ||
        ref.symbols.includes(targetSymbol);
      if (!matchesSymbol) continue;

      let invoked = true;
      let callCount = 1;

      if (targetSymbol && !ref.isReExported) {
        const trace = traceSymbolInvocations(
          content,
          filePath,
          ref.importedIdentifiers,
          targetSymbol,
        );
        invoked = trace.invoked;
        callCount = trace.callCount;
        totalInvocations += callCount;
      }

      evidence.push({
        filePath,
        matchType: ref.matchType,
        importedSymbols: ref.symbols,
        symbol: targetSymbol,
        invoked,
        callCount,
      });
    }
  }

  return { evidence, hasReExport, totalInvocations };
}

/** No source file mentions the package: it can still be reached through a direct dependency. */
function assessUnreferencedPackage(
  scan: PackageScan,
  cwd: string,
  packageName: string,
): ReachabilityAssessment {
  const transitivePath = findTransitiveDependencyPath(
    cwd,
    packageName,
    scan.importedDirectPackages,
  );
  if (transitivePath) {
    return {
      packageName,
      status: "reachable",
      reason: `Package '${packageName}' is a transitive dependency of imported package '${transitivePath.directDependency}'`,
      reachabilityBasis: "transitive-path-found",
      evidence: [],
    };
  }

  return {
    packageName,
    status: "not-reachable",
    reason: `No source files reference '${packageName}'`,
    reachabilityBasis: "import-present",
    justification: "code_not_in_execute_path",
    evidence: [],
  };
}

/** The package is imported and a specific symbol was asked about. */
function assessTargetSymbol(input: {
  packageName: string;
  targetSymbol: string;
  evidence: ReachabilityEvidence[];
  hasReExport: boolean;
  totalInvocations: number;
}): ReachabilityAssessment {
  const { packageName, targetSymbol, evidence, hasReExport, totalInvocations } = input;

  if (hasReExport || totalInvocations > 0) {
    return {
      packageName,
      status: "reachable",
      reason: hasReExport
        ? `Package '${packageName}' re-exports symbols to external consumers`
        : `Found ${totalInvocations} call-site(s) invoking vulnerable symbol '${targetSymbol}' across ${evidence.filter((e) => e.invoked).length} file(s)`,
      reachabilityBasis: "call-path-found",
      evidence,
    };
  }

  return {
    packageName,
    status: "not-reachable",
    reason: `Package '${packageName}' is imported but vulnerable symbol '${targetSymbol}' is never invoked in any execution path`,
    reachabilityBasis: "call-graph-uninvoked",
    justification: "code_not_in_execute_path",
    evidence,
  };
}
