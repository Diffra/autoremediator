/**
 * Known library breaking-change migrations: `pkg.method(...)` call sites become a named import.
 *
 * rimraf, glob and mkdirp moved `.sync` to a `<name>Sync` export; uuid moved `.v4` to a `v4`
 * export. Each migration rewrites the member call and, when the file has a default import of the
 * package, replaces that import with the named one.
 */
import { visitNodes, type TextEdit } from "./ast-edits.js";
import type { ImportBindings } from "./import-bindings.js";

interface LibraryMigration {
  packageName: string;
  /** Member of the old default export that call sites use, e.g. `sync`. */
  method: string;
  /** Substrings of the compiler output that signal this migration applies. */
  diagnosticMarkers: string[];
  /** Replacement for the `pkg.method` callee. */
  replacement: string;
  /** Replacement for the default import declaration. */
  importStatement: string;
}

const LIBRARY_MIGRATIONS: LibraryMigration[] = [
  {
    packageName: "rimraf",
    method: "sync",
    diagnosticMarkers: ["sync", "rimrafSync"],
    replacement: "rimrafSync",
    importStatement: `import { rimrafSync } from "rimraf";`,
  },
  {
    packageName: "uuid",
    method: "v4",
    diagnosticMarkers: ["v4", "uuidv4"],
    replacement: "uuidv4",
    importStatement: `import { v4 as uuidv4 } from "uuid";`,
  },
  {
    packageName: "glob",
    method: "sync",
    diagnosticMarkers: ["sync", "globSync"],
    replacement: "globSync",
    importStatement: `import { globSync } from "glob";`,
  },
  {
    packageName: "mkdirp",
    method: "sync",
    diagnosticMarkers: ["sync", "mkdirpSync"],
    replacement: "mkdirpSync",
    importStatement: `import { mkdirpSync } from "mkdirp";`,
  },
];

export interface LibraryMigrationContext {
  program: any;
  content: string;
  packageName: string;
  diagnosticError: string;
  bindings: ImportBindings;
}

export function planLibraryMigrations(context: LibraryMigrationContext): TextEdit[] {
  const edits: TextEdit[] = [];
  for (const migration of LIBRARY_MIGRATIONS) {
    if (migration.packageName === context.packageName && isMigrationNeeded(migration, context)) {
      edits.push(...planMigrationEdits(migration, context));
    }
  }
  return edits;
}

function isMigrationNeeded(migration: LibraryMigration, context: LibraryMigrationContext): boolean {
  const { content, diagnosticError, bindings } = context;
  const { defaultLocalName } = bindings;
  return (
    migration.diagnosticMarkers.some((marker) => diagnosticError.includes(marker)) ||
    content.includes(`${migration.packageName}.${migration.method}(`) ||
    Boolean(defaultLocalName && content.includes(`${defaultLocalName}.${migration.method}(`))
  );
}

function planMigrationEdits(
  migration: LibraryMigration,
  context: LibraryMigrationContext,
): TextEdit[] {
  const { program, bindings } = context;
  const targetLocal = bindings.defaultLocalName || migration.packageName;
  const edits: TextEdit[] = [];

  visitNodes(program, (node) => {
    if (
      node.type === "CallExpression" &&
      node.callee?.type === "MemberExpression" &&
      node.callee.object?.type === "Identifier" &&
      node.callee.object.name === targetLocal &&
      node.callee.property?.name === migration.method
    ) {
      edits.push({
        start: node.callee.start,
        end: node.callee.end,
        replacement: migration.replacement,
      });
    }
  });

  if (bindings.defaultImportDecl) {
    edits.push({
      start: bindings.defaultImportDecl.start,
      end: bindings.defaultImportDecl.end,
      replacement: migration.importStatement,
    });
  }
  return edits;
}
