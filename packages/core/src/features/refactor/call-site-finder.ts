/**
 * Call-Site Finder for Breaking Change Remediation
 *
 * Scans project source files using oxc-parser AST parsing to identify
 * all call sites, import statements, member expressions, and argument usages
 * referencing a target dependency without false positives from comments or strings.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { parseSync } from "oxc-parser";

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"]);
const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  ".turbo",
  ".pnpm-store",
]);

export type ImportKind =
  | "default"
  | "namespace"
  | "named"
  | "require-default"
  | "require-destructured";

export interface ImportReference {
  localName: string;
  importedName: string;
  isDefault: boolean;
  isNamespace: boolean;
  kind?: ImportKind;
  start?: number;
  end?: number;
}

export interface AstCallSite {
  start: number;
  end: number;
  line: number;
  column: number;
  calleeText: string;
  expressionType: "call" | "property-access";
  localSymbol: string;
  memberName?: string;
  argumentCount: number;
  argumentSpans: Array<{ start: number; end: number; text: string }>;
}

export interface ConsumerCallSite {
  filePath: string;
  sourceContent: string;
  importSources: string[];
  imports: ImportReference[];
  referencedLines: number[];
  callSites?: AstCallSite[];
}

function* walkFiles(dir: string): Generator<string> {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      yield* walkFiles(full);
    } else {
      const ext = full.slice(full.lastIndexOf("."));
      if (SOURCE_EXTENSIONS.has(ext)) {
        yield full;
      }
    }
  }
}

type AstNode = any;

const isTargetSource = (source: string, packageName: string): boolean =>
  source === packageName || source.startsWith(`${packageName}/`);

interface Imports {
  imports: ImportReference[];
  importSources: string[];
  localNames: Set<string>;
}

/** `import x, { y as z } from "pkg"`: one reference per local name. */
function readImportDeclaration(statement: AstNode, found: Imports): void {
  for (const spec of statement.specifiers || []) {
    const localName = spec.local?.name || "";
    if (!localName) continue;
    found.localNames.add(localName);
    const position = { start: spec.local?.start, end: spec.local?.end };
    if (spec.type === "ImportDefaultSpecifier") {
      found.imports.push({
        localName,
        importedName: "default",
        isDefault: true,
        isNamespace: false,
        kind: "default",
        ...position,
      });
    } else if (spec.type === "ImportNamespaceSpecifier") {
      found.imports.push({
        localName,
        importedName: "*",
        isDefault: false,
        isNamespace: true,
        kind: "namespace",
        ...position,
      });
    } else if (spec.type === "ImportSpecifier") {
      found.imports.push({
        localName,
        importedName: spec.imported?.name || localName,
        isDefault: false,
        isNamespace: false,
        kind: "named",
        ...position,
      });
    }
  }
}

/** `const x = require("pkg")` and `const { a, b: c } = require("pkg")`. */
function readRequireDeclarator(decl: AstNode, found: Imports): void {
  if (decl.id?.type === "Identifier") {
    found.localNames.add(decl.id.name);
    found.imports.push({
      localName: decl.id.name,
      importedName: "default",
      isDefault: true,
      isNamespace: false,
      kind: "require-default",
    });
  } else if (decl.id?.type === "ObjectPattern") {
    for (const prop of decl.id.properties || []) {
      const localName = prop.value?.name || prop.key?.name;
      if (!localName) continue;
      found.localNames.add(localName);
      found.imports.push({
        localName,
        importedName: prop.key?.name || localName,
        isDefault: false,
        isNamespace: false,
        kind: "require-destructured",
      });
    }
  }
}

/** Every import or require of the package at the top level of a file. */
function findImports(program: { body: AstNode[] }, packageName: string): Imports {
  const found: Imports = { imports: [], importSources: [], localNames: new Set() };
  for (const statement of program.body) {
    if (statement.type === "ImportDeclaration" && statement.source?.value) {
      const source = String(statement.source.value);
      if (isTargetSource(source, packageName)) {
        found.importSources.push(source);
        readImportDeclaration(statement, found);
      }
    }
    if (statement.type !== "VariableDeclaration") continue;
    for (const decl of statement.declarations || []) {
      const init = decl.init;
      const isRequire =
        init?.type === "CallExpression" &&
        init.callee?.type === "Identifier" &&
        init.callee.name === "require" &&
        init.arguments?.[0]?.value;
      if (!isRequire) continue;
      const source = String(init.arguments[0].value);
      if (isTargetSource(source, packageName)) {
        found.importSources.push(source);
        readRequireDeclarator(decl, found);
      }
    }
  }
  return found;
}

/** Maps a character offset to a 1-based line and column. */
function createLineLookup(content: string): (offset: number) => { line: number; column: number } {
  const lineStarts: number[] = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === "\n") lineStarts.push(i + 1);
  }
  return (offset) => {
    let low = 0;
    let high = lineStarts.length - 1;
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      if (lineStarts[mid]! <= offset) {
        if (mid === lineStarts.length - 1 || lineStarts[mid + 1]! > offset) {
          return { line: mid + 1, column: offset - lineStarts[mid]! + 1 };
        }
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return { line: 1, column: offset + 1 };
  };
}

/** What walking a file's AST collects: genuine uses of the imported names, not strings or comments. */
interface UseScan {
  content: string;
  localNames: Set<string>;
  lineOf: (offset: number) => { line: number; column: number };
  referencedLines: Set<number>;
  callSites: AstCallSite[];
}

function readCall(node: AstNode, scan: UseScan): void {
  let localSymbol = "";
  let memberName: string | undefined;
  if (node.callee?.type === "Identifier" && scan.localNames.has(node.callee.name)) {
    localSymbol = node.callee.name;
  } else if (
    node.callee?.type === "MemberExpression" &&
    node.callee.object?.type === "Identifier" &&
    scan.localNames.has(node.callee.object.name)
  ) {
    localSymbol = node.callee.object.name;
    memberName = node.callee.property?.name;
  }
  if (!localSymbol) return;
  const { line, column } = scan.lineOf(node.start);
  scan.referencedLines.add(line);
  const args: AstNode[] = node.arguments || [];
  scan.callSites.push({
    start: node.start,
    end: node.end,
    line,
    column,
    calleeText: scan.content.slice(node.callee.start, node.callee.end),
    expressionType: "call",
    localSymbol,
    memberName,
    argumentCount: args.length,
    argumentSpans: args.map((arg) => ({
      start: arg.start,
      end: arg.end,
      text: scan.content.slice(arg.start, arg.end),
    })),
  });
}

function readMemberAccess(node: AstNode, parentType: string | undefined, scan: UseScan): void {
  if (node.object?.type !== "Identifier" || !scan.localNames.has(node.object.name)) return;
  const { line, column } = scan.lineOf(node.start);
  scan.referencedLines.add(line);
  if (parentType === "CallExpression") return;
  scan.callSites.push({
    start: node.start,
    end: node.end,
    line,
    column,
    calleeText: scan.content.slice(node.start, node.end),
    expressionType: "property-access",
    localSymbol: node.object.name,
    memberName: node.property?.name,
    argumentCount: 0,
    argumentSpans: [],
  });
}

function scanUses(node: AstNode, scan: UseScan, parentType?: string): void {
  if (!node || typeof node !== "object") return;
  if (node.type === "CallExpression") {
    readCall(node, scan);
  } else if (node.type === "MemberExpression") {
    readMemberAccess(node, parentType, scan);
  } else if (
    node.type === "Identifier" &&
    scan.localNames.has(node.name) &&
    !parentType?.startsWith("Import")
  ) {
    scan.referencedLines.add(scan.lineOf(node.start).line);
  }
  for (const key of Object.keys(node)) {
    if (key === "parent") continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) scanUses(item, scan, node.type);
    } else if (child && typeof child === "object") {
      scanUses(child, scan, node.type);
    }
  }
}

/** The use of `packageName` in one file, or undefined when the file does not import it. */
function findCallSitesInFile(
  filePath: string,
  content: string,
  packageName: string,
): ConsumerCallSite | undefined {
  const parseResult = parseSync(filePath, content);
  if (!parseResult.program) return undefined;
  const program = parseResult.program as unknown as { body: AstNode[] };

  const { imports, importSources, localNames } = findImports(program, packageName);
  if (imports.length === 0 && importSources.length === 0) return undefined;

  const scan: UseScan = {
    content,
    localNames,
    lineOf: createLineLookup(content),
    referencedLines: new Set(),
    callSites: [],
  };
  scanUses(program, scan);
  return {
    filePath,
    sourceContent: content,
    importSources,
    imports,
    referencedLines: [...scan.referencedLines].toSorted((a, b) => a - b),
    callSites: scan.callSites,
  };
}

export function findPackageCallSites(cwd: string, packageName: string): ConsumerCallSite[] {
  const callSites: ConsumerCallSite[] = [];
  for (const filePath of walkFiles(cwd)) {
    let content: string;
    try {
      content = readFileSync(filePath, "utf8");
    } catch {
      continue;
    }
    // Quick pre-filter to avoid unnecessary parsing
    if (!content.includes(packageName)) continue;
    try {
      const found = findCallSitesInFile(filePath, content, packageName);
      if (found) callSites.push(found);
    } catch {
      // Ignore parser syntax errors in consumer files
    }
  }
  return callSites;
}
