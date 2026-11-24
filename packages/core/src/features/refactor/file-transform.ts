/**
 * Applies the codemods to one source file and returns the rewritten text.
 *
 * Steps run in a fixed order against the original parse; their edits are merged and applied once,
 * then any caller-supplied argument transform runs on the result.
 */
import { parseSync } from "oxc-parser";

import { transformCallArguments, type ArgumentTransformOptions } from "./argument-transforms.js";
import { applyEdits, type TextEdit } from "./ast-edits.js";
import {
  planDefaultToNamespaceImport,
  planNamespaceToDefaultImport,
  planSubpathImportMigration,
  planSuggestedRenames,
} from "./diagnostic-migrations.js";
import { collectImportBindings } from "./import-bindings.js";
import { planLibraryMigrations } from "./library-migrations.js";

/**
 * Applies deterministic and compiler-guided AST transformations to a source file.
 */
export function transformFileContent(
  content: string,
  packageName: string,
  diagnosticError: string,
  filePath?: string,
  argumentTransforms?: ArgumentTransformOptions,
): { modified: boolean; newContent: string } {
  let currentContent = content;
  let modified = false;

  const parseResult = parseSync(filePath ?? "file.ts", currentContent);
  if (!parseResult.program) {
    return { modified: false, newContent: content };
  }

  const program: any = parseResult.program;
  const body: any[] = program.body || [];
  const bindings = collectImportBindings(body, packageName);

  const edits: TextEdit[] = [
    ...planSubpathImportMigration(bindings, packageName, diagnosticError),
    ...planLibraryMigrations({
      program,
      content: currentContent,
      packageName,
      diagnosticError,
      bindings,
    }),
    ...planDefaultToNamespaceImport(bindings, packageName, diagnosticError),
    ...planNamespaceToDefaultImport(bindings, body, packageName, diagnosticError),
    ...planSuggestedRenames(program, currentContent, diagnosticError),
  ];

  if (edits.length > 0) {
    currentContent = applyEdits(currentContent, edits);
    modified = true;
  }

  if (argumentTransforms) {
    const argResult = transformCallArguments(currentContent, {
      ...argumentTransforms,
      filePath,
    });
    if (argResult.modified) {
      currentContent = argResult.newContent;
      modified = true;
    }
  }

  return { modified, newContent: currentContent };
}
