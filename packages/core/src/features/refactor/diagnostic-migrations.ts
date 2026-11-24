/**
 * Migrations driven by the compiler's own complaint: a removed subpath import, a default export
 * that became a namespace (or the reverse), and "Did you mean 'xyz'?" renames.
 */
import { visitNodes, type TextEdit } from "./ast-edits.js";
import { parseCompilerDiagnostics, type ParsedTsDiagnostic } from "./compiler-diagnostics.js";
import type { ImportBindings } from "./import-bindings.js";

/**
 * Subpath import migration: `import v4 from "uuid/v4"` becomes `import { v4 as v4 } from "uuid";`.
 */
export function planSubpathImportMigration(
  bindings: ImportBindings,
  packageName: string,
  diagnosticError: string,
): TextEdit[] {
  const { subpathImportDecl, defaultLocalName, subpathName } = bindings;
  const missingSubpath =
    diagnosticError.includes(`Cannot find module '${packageName}/`) ||
    diagnosticError.includes(`Cannot find module "${packageName}/`);
  if (!subpathImportDecl || !missingSubpath) {
    return [];
  }
  const local = defaultLocalName || subpathName || "default";
  return [
    {
      start: subpathImportDecl.start,
      end: subpathImportDecl.end,
      replacement: `import { ${subpathName} as ${local} } from "${packageName}";`,
    },
  ];
}

/**
 * Default export removed in favor of namespace (TS2614, TS1192, "no default export").
 */
export function planDefaultToNamespaceImport(
  bindings: ImportBindings,
  packageName: string,
  diagnosticError: string,
): TextEdit[] {
  const { defaultImportDecl, defaultLocalName } = bindings;
  const defaultRemoved =
    diagnosticError.includes("no default export") ||
    diagnosticError.includes("has no exported member 'default'") ||
    diagnosticError.includes("has no exported member default") ||
    diagnosticError.includes("TS2614") ||
    diagnosticError.includes("TS1192");
  if (!defaultImportDecl || !defaultLocalName || !defaultRemoved) {
    return [];
  }
  return [
    {
      start: defaultImportDecl.start,
      end: defaultImportDecl.end,
      replacement: `import * as ${defaultLocalName} from "${packageName}";`,
    },
  ];
}

/**
 * Namespace import deprecated in favor of default import (TS1259).
 */
export function planNamespaceToDefaultImport(
  bindings: ImportBindings,
  body: any[],
  packageName: string,
  diagnosticError: string,
): TextEdit[] {
  const { namespaceLocalName } = bindings;
  const defaultRequired =
    diagnosticError.includes("can only be used with a default import") ||
    diagnosticError.includes("only be used with a default import") ||
    diagnosticError.includes("TS1259");
  if (!namespaceLocalName || !defaultRequired) {
    return [];
  }
  const edits: TextEdit[] = [];
  for (const statement of body) {
    if (statement.type === "ImportDeclaration" && String(statement.source?.value) === packageName) {
      edits.push({
        start: statement.start,
        end: statement.end,
        replacement: `import ${namespaceLocalName} from "${packageName}";`,
      });
    }
  }
  return edits;
}

/**
 * Compiler feedback: "Did you mean 'XYZ'?" auto-replacement of a missing member.
 */
export function planSuggestedRenames(
  program: any,
  content: string,
  diagnosticError: string,
): TextEdit[] {
  const edits: TextEdit[] = [];
  for (const diag of parseCompilerDiagnostics(diagnosticError)) {
    if (diag.missingMember && diag.suggestedSymbol) {
      const getLine = createLineLookup(content);
      edits.push(...planRenamesForDiagnostic(program, diag, getLine));
    }
  }
  return edits;
}

function planRenamesForDiagnostic(
  program: any,
  diag: ParsedTsDiagnostic,
  getLine: (offset: number) => number,
): TextEdit[] {
  const missing = diag.missingMember;
  const suggested = diag.suggestedSymbol ?? "";
  const edits: TextEdit[] = [];

  visitNodes(program, (node) => {
    if (node.type === "MemberExpression" && node.property?.name === missing) {
      const lineMatches = !diag.line || diag.line === getLine(node.start);
      if (lineMatches) {
        edits.push({
          start: node.property.start,
          end: node.property.end,
          replacement: suggested,
        });
      }
    }
    if (
      node.type === "ImportSpecifier" &&
      (node.imported?.name === missing || node.local?.name === missing)
    ) {
      edits.push({
        start: node.local.start,
        end: node.local.end,
        replacement: suggested,
      });
    }
  });
  return edits;
}

/**
 * Returns a function mapping a character offset to its 1-based line number.
 */
function createLineLookup(content: string): (offset: number) => number {
  const lineStarts: number[] = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === "\n") {
      lineStarts.push(i + 1);
    }
  }
  return (offset) => {
    let low = 0;
    let high = lineStarts.length - 1;
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      if (lineStarts[mid]! <= offset) {
        if (mid === lineStarts.length - 1 || lineStarts[mid + 1]! > offset) {
          return mid + 1;
        }
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return 1;
  };
}
