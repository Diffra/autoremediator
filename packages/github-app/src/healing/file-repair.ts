/**
 * Pattern-based repairs for a single file's content, driven by structured CI diagnostics.
 *
 * Each repair is one named step; `repairFileContent` applies them to every finding in order.
 */
import type { DiagnosticFinding } from "../diagnostics/log-parser.js";

/**
 * Attempts targeted healing repairs on file content using structured diagnostics.
 */
export function repairFileContent(content: string, findings: DiagnosticFinding[]): string {
  let repaired = content;

  for (const finding of findings) {
    const msg = finding.message;
    repaired = repairDefaultImportMismatch(repaired, msg);
    repaired = repairExportEqualsImport(repaired, msg);

    const suggested = applyCompilerSuggestion(repaired, finding);
    if (suggested === undefined) {
      continue;
    }
    repaired = removeUnusedImport(suggested, finding);
  }

  return repaired;
}

function escapeRegex(str: string): string {
  return str.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

/** TypeScript ESM default export mismatch (TS2614, TS1192, "has no default export"). */
function repairDefaultImportMismatch(content: string, msg: string): string {
  if (
    !(
      msg.includes("no default export") ||
      msg.includes("has no exported member 'default'") ||
      msg.includes("TS2614") ||
      msg.includes("TS1192")
    )
  ) {
    return content;
  }

  // e.g. Module '"chalk"' has no default export.
  const pkgMatch =
    /Module\s+['"]([^'"]+)['"]\s+has\s+no\s+default/i.exec(msg) ??
    /Module\s+['"]([^'"]+)['"]/i.exec(msg) ??
    /['"]([^'"]+)['"]/.exec(msg);
  const targetPkg = pkgMatch ? pkgMatch[1] : undefined;

  const importRegex = targetPkg
    ? new RegExp(`import\\s+([a-zA-Z0-9_$]+)\\s+from\\s+['"]${escapeRegex(targetPkg)}['"];?`, "g")
    : /import\s+([a-zA-Z0-9_$]+)\s+from\s+['"]([^'"]+)['"];?/g;

  return content.replace(importRegex, (_match, id, matchedPkg) => {
    const pkg = targetPkg || matchedPkg;
    return `import * as ${id} from "${pkg}";`;
  });
}

/** TypeScript CJS "export =" default import mismatch (TS1259). */
function repairExportEqualsImport(content: string, msg: string): string {
  if (!(msg.includes("can only be used with a default import") || msg.includes("TS1259"))) {
    return content;
  }

  const pkgMatch = /Module\s+['"]([^'"]+)['"]/i.exec(msg) ?? /['"]([^'"]+)['"]/.exec(msg);
  const targetPkg = pkgMatch ? pkgMatch[1] : undefined;

  const starImportRegex = targetPkg
    ? new RegExp(
        `import\\s+\\*\\s+as\\s+([a-zA-Z0-9_$]+)\\s+from\\s+['"]${escapeRegex(targetPkg)}['"];?`,
        "g",
      )
    : /import\s+\*\s+as\s+([a-zA-Z0-9_$]+)\s+from\s+['"]([^'"]+)['"];?/g;

  return content.replace(starImportRegex, (_match, id, matchedPkg) => {
    const pkg = targetPkg || matchedPkg;
    return `import ${id} from "${pkg}";`;
  });
}

/**
 * Compiler suggestion: "Did you mean 'XYZ'?". Returns the content unchanged when the message has
 * no suggestion, and `undefined` when the suggested name is not already in the file, which ends
 * the repairs for this finding.
 */
function applyCompilerSuggestion(content: string, finding: DiagnosticFinding): string | undefined {
  const msg = finding.message;
  const suggestionMatch = /Did you mean ['"]([a-zA-Z0-9_$]+)['"]\?/.exec(msg);
  const missingMatch =
    /has no exported member ['"]([a-zA-Z0-9_$]+)['"]/.exec(msg) ??
    /Property ['"]([a-zA-Z0-9_$]+)['"] does not exist/.exec(msg);

  if (!suggestionMatch || !missingMatch) {
    return content;
  }
  const oldSymbol = missingMatch[1]!;
  const newSymbol = suggestionMatch[1]!;

  // The suggestion is CI text. It is applied only when that identifier is already in this
  // file, so the output can pick which existing name is used but never introduce a new one.
  if (!new RegExp(`(?<![\\w$])${escapeRegex(newSymbol)}(?![\\w$])`).test(content)) {
    return undefined;
  }

  if (finding.line && finding.line > 0) {
    // Target specifically the line indicated by the compiler diagnostic
    const lines = content.split("\n");
    const idx = finding.line - 1;
    if (idx >= 0 && idx < lines.length) {
      lines[idx] = lines[idx]!.replaceAll(
        new RegExp(`\\b${escapeRegex(oldSymbol)}\\b`, "g"),
        newSymbol,
      );
      return lines.join("\n");
    }
    return content;
  }
  // Replace member expression .oldSymbol -> .newSymbol
  return content.replaceAll(new RegExp(`\\.${escapeRegex(oldSymbol)}\\b`, "g"), `.${newSymbol}`);
}

/** Linter: unused import removal. */
function removeUnusedImport(content: string, finding: DiagnosticFinding): string {
  if (
    !finding.ruleId ||
    !(finding.ruleId.includes("no-unused-vars") || finding.ruleId.includes("unused-imports"))
  ) {
    return content;
  }
  const unusedVarMatch = /['"]([a-zA-Z0-9_$]+)['"]\s+is\s+(?:defined|imported)/.exec(
    finding.message,
  );
  if (!unusedVarMatch) {
    return content;
  }

  const unusedVar = unusedVarMatch[1]!;
  const lines = content.split("\n");
  const idx = locateImportLine(lines, finding.line, unusedVar);
  if (idx < 0 || idx >= lines.length || !lines[idx]!.includes("import")) {
    return content;
  }

  const line = lines[idx]!;
  if (isSoleImportOf(line, unusedVar)) {
    lines.splice(idx, 1);
  } else {
    const stripped = stripImportedName(line, unusedVar);
    if (/^\s*import\s*(?:type\s+)?\{\s*\}\s*from\s*['"][^'"]+['"];?\s*$/.test(stripped)) {
      lines.splice(idx, 1);
    } else {
      lines[idx] = stripped;
    }
  }
  return lines.join("\n");
}

function locateImportLine(lines: string[], line: number | undefined, unusedVar: string): number {
  const idx = line && line > 0 ? line - 1 : -1;
  if (idx >= 0 && idx < lines.length && lines[idx]?.includes("import")) {
    return idx;
  }
  // If no line or line didn't match, locate line containing the unused import
  return lines.findIndex(
    (l) => l.includes("import") && new RegExp(`\\b${escapeRegex(unusedVar)}\\b`).test(l),
  );
}

function isSoleImportOf(line: string, name: string): boolean {
  const soleNamedImport = new RegExp(
    `^\\s*import\\s*(?:type\\s+)?\\{\\s*(?:type\\s+)?${escapeRegex(name)}\\s*,?\\s*\\}\\s*from\\s*['"][^'"]+['"];?\\s*$`,
  );
  const defaultImport = new RegExp(
    `^\\s*import\\s+(?:type\\s+)?${escapeRegex(name)}\\s+from\\s*['"][^'"]+['"];?\\s*$`,
  );
  return soleNamedImport.test(line) || defaultImport.test(line);
}

function stripImportedName(line: string, name: string): string {
  return line
    .replace(new RegExp(`,\\s*${escapeRegex(name)}\\b`), "")
    .replace(new RegExp(`\\b${escapeRegex(name)}\\s*,\\s*`), "");
}
