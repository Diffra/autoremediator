/**
 * Finds the places a source file refers to a package: static imports, dynamic imports, CommonJS
 * `require` calls and re-exports. Also records every external package the file imports, so a
 * caller can look for transitive paths.
 */
import { isAbsolute } from "node:path";

import { parseSync, type ParseResult } from "oxc-parser";

import { type AstNode, walkAst } from "./ast-walk.js";
import { resolveAliasedPath, type TsconfigPathsConfig } from "./tsconfig-paths.js";
import type { ReachabilityEvidence } from "./types.js";

export interface ExtractedReference {
  matchType: ReachabilityEvidence["matchType"];
  symbols: string[];
  importedIdentifiers: Map<string, string>; // local variable name -> imported member name
  isReExported: boolean;
}

export function toRootPackageName(importSource: string): string {
  if (importSource.startsWith("@")) {
    const parts = importSource.split("/");
    return parts.slice(0, 2).join("/");
  }
  return importSource.split("/")[0] ?? importSource;
}

/**
 * Extracts package references and imported symbols using the Oxc AST parser.
 */
export function extractPackageReferences(
  filename: string,
  content: string,
  packageName: string,
  tsconfig?: TsconfigPathsConfig,
  outImportedDirectPackages?: Set<string>,
): ExtractedReference[] {
  const results: ExtractedReference[] = [];

  let parseResult: ParseResult | undefined;
  try {
    parseResult = parseSync(filename, content);
  } catch {
    return results;
  }

  if (!parseResult?.program) return results;

  const scan: ReferenceScan = { packageName, tsconfig, outImportedDirectPackages, results };
  walkAst(parseResult.program as unknown as AstNode, (node) => visitNode(node, scan));

  return results;
}

interface ReferenceScan {
  packageName: string;
  tsconfig: TsconfigPathsConfig | undefined;
  outImportedDirectPackages: Set<string> | undefined;
  results: ExtractedReference[];
}

function matchesPackage(
  sourceValue: string,
  packageName: string,
  tsconfig?: TsconfigPathsConfig,
): boolean {
  if (sourceValue === packageName || sourceValue.startsWith(`${packageName}/`)) {
    return true;
  }
  const resolved = resolveAliasedPath(sourceValue, tsconfig);
  if (resolved && (resolved.includes(`/${packageName}/`) || resolved.endsWith(`/${packageName}`))) {
    return true;
  }
  return false;
}

function visitNode(node: AstNode, scan: ReferenceScan): void {
  switch (node.type) {
    case "ImportDeclaration": {
      collectStaticImport(node, scan);
      break;
    }
    case "ImportExpression": {
      collectDynamicImport(node, scan);
      break;
    }
    case "CallExpression": {
      collectRequireCall(node, scan);
      break;
    }
    case "ExportNamedDeclaration":
    case "ExportAllDeclaration": {
      collectReExport(node, scan);
      break;
    }
    default: {
      break;
    }
  }
}

/** Notes an external (non-relative, non-absolute) module source as a package the file imports. */
function recordExternalSource(value: string | undefined, scan: ReferenceScan): void {
  if (value && !value.startsWith(".") && !isAbsolute(value)) {
    scan.outImportedDirectPackages?.add(toRootPackageName(value));
  }
}

/** 1. Static Import Declarations: import ... from 'pkg' */
function collectStaticImport(node: AstNode, scan: ReferenceScan): void {
  const source = node.source as { value?: string } | undefined;
  recordExternalSource(source?.value, scan);
  if (!source?.value || !matchesPackage(source.value, scan.packageName, scan.tsconfig)) return;

  const symbols: string[] = [];
  const importedIdentifiers = new Map<string, string>();
  const specifiers = (node.specifiers ?? []) as AstNode[];

  for (const spec of specifiers) {
    if (spec.type === "ImportSpecifier") {
      const imported = spec.imported as { name?: string; value?: string } | undefined;
      const local = spec.local as { name?: string } | undefined;
      const importedName = imported?.name ?? imported?.value ?? local?.name;
      const localName = local?.name ?? importedName;
      if (importedName && localName) {
        symbols.push(importedName);
        importedIdentifiers.set(localName, importedName);
      }
    } else if (spec.type === "ImportDefaultSpecifier") {
      const local = spec.local as { name?: string } | undefined;
      symbols.push("default");
      if (local?.name) importedIdentifiers.set(local.name, "default");
    } else if (spec.type === "ImportNamespaceSpecifier") {
      const local = spec.local as { name?: string } | undefined;
      symbols.push("*");
      if (local?.name) importedIdentifiers.set(local.name, "*");
    }
  }

  scan.results.push({
    matchType: "import",
    symbols: symbols.length > 0 ? symbols : ["*"],
    importedIdentifiers,
    isReExported: false,
  });
}

/** 2. Dynamic Import Expressions: import('pkg') */
function collectDynamicImport(node: AstNode, scan: ReferenceScan): void {
  const source = node.source as { value?: string } | undefined;
  recordExternalSource(source?.value, scan);
  if (source?.value && matchesPackage(source.value, scan.packageName, scan.tsconfig)) {
    scan.results.push({
      matchType: "dynamic-import",
      symbols: ["*"],
      importedIdentifiers: new Map(),
      isReExported: false,
    });
  }
}

/** 3. CommonJS Require Calls: require('pkg') */
function collectRequireCall(node: AstNode, scan: ReferenceScan): void {
  if (
    (node.callee as { name?: string })?.name !== "require" ||
    !Array.isArray(node.arguments) ||
    node.arguments.length === 0
  ) {
    return;
  }
  const firstArg = node.arguments[0] as { value?: string } | undefined;
  const value = typeof firstArg?.value === "string" ? firstArg.value : undefined;
  recordExternalSource(value, scan);
  if (value && matchesPackage(value, scan.packageName, scan.tsconfig)) {
    scan.results.push({
      matchType: "require",
      symbols: ["*"],
      importedIdentifiers: new Map(),
      isReExported: false,
    });
  }
}

/** 4. Re-export Declarations: export ... from 'pkg' */
function collectReExport(node: AstNode, scan: ReferenceScan): void {
  const source = node.source as { value?: string } | undefined;
  recordExternalSource(source?.value, scan);
  if (!source?.value || !matchesPackage(source.value, scan.packageName, scan.tsconfig)) return;

  const symbols: string[] = [];
  if (node.type === "ExportAllDeclaration") {
    symbols.push("*");
  } else {
    const specifiers = (node.specifiers ?? []) as AstNode[];
    for (const spec of specifiers) {
      const local = spec.local as { name?: string; value?: string } | undefined;
      const exported = spec.exported as { name?: string; value?: string } | undefined;
      const name = exported?.name ?? exported?.value ?? local?.name ?? local?.value;
      if (name) symbols.push(name);
    }
  }
  scan.results.push({
    matchType: "re-export",
    symbols: symbols.length > 0 ? symbols : ["*"],
    importedIdentifiers: new Map(),
    isReExported: true,
  });
}
