import { parseSync } from "oxc-parser";

import { toRootPackageName } from "../reachability/check-reachability.js";
import { collectPackageFiles, readText, type PackageFiles } from "./files.js";

export type ReferenceKind =
  | "import"
  | "type-import"
  | "require"
  | "dynamic-import"
  | "resolve"
  | "reference";

export interface PackageReference {
  kinds: Set<ReferenceKind>;
  /** Exports taken from the package: names, `default`, or `*` when the whole module is used or it cannot be told. */
  symbols: Set<string>;
  /** First few files, relative to the package directory. */
  files: string[];
}

/** What one package directory's files say about which dependencies they use. */
export interface PackageUsage {
  /** Direct imports, requires, resolves and type references, by root package name. */
  references: Map<string, PackageReference>;
  /** A package name appears as a string (a mock path, a plugin list, a dynamic specifier). */
  mentions: Map<string, string[]>;
  /** Config, CI and script text: every token and where it was first seen. */
  tokens: Map<string, string>;
  /** Files that load a module by a name only known at runtime. */
  dynamicLoadFiles: string[];
  /** Files that could not be parsed or read in full. */
  unparsedFiles: string[];
  sourceFiles: number;
  configFiles: number;
}

export function emptyUsage(): PackageUsage {
  return {
    references: new Map(),
    mentions: new Map(),
    tokens: new Map(),
    dynamicLoadFiles: [],
    unparsedFiles: [],
    sourceFiles: 0,
    configFiles: 0,
  };
}

const MAX_EVIDENCE_FILES = 5;

interface AstNode {
  type: string;
  [key: string]: unknown;
}

const isNode = (value: unknown): value is AstNode =>
  typeof value === "object" &&
  value !== null &&
  typeof (value as { type?: unknown }).type === "string";

/** `require("x")`, `import("x")` and `import "x"` all name their module with a static string. */
function staticSpecifier(node: unknown): string | undefined {
  if (!isNode(node)) return undefined;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral") {
    const quasis = node.quasis as { value?: { cooked?: string } }[] | undefined;
    const expressions = node.expressions as unknown[] | undefined;
    if (quasis?.length === 1 && (expressions?.length ?? 0) === 0) {
      return quasis[0]?.value?.cooked ?? undefined;
    }
  }
  return undefined;
}

/** A computed specifier that starts with `.` or `/` loads a project file, not a dependency. */
function looksRelative(node: unknown): boolean {
  if (!isNode(node)) return false;
  if (node.type === "TemplateLiteral") {
    const first =
      (node.quasis as { value?: { cooked?: string } }[] | undefined)?.[0]?.value?.cooked ?? "";
    return first.startsWith(".") || first.startsWith("/");
  }
  if (node.type === "BinaryExpression") return looksRelative(node.left);
  if (node.type === "Literal") return typeof node.value === "string" && /^[./]/.test(node.value);
  return false;
}

const isDependencySpecifier = (specifier: string): boolean =>
  specifier.length > 0 &&
  !/^[./#]/.test(specifier) &&
  !/^[a-z]+:/i.test(specifier) &&
  !specifier.includes(" ");

function addReference(
  usage: PackageUsage,
  specifier: string,
  kind: ReferenceKind,
  symbols: Iterable<string>,
  file: string,
): void {
  if (!isDependencySpecifier(specifier)) return;
  const name = toRootPackageName(specifier);
  let reference = usage.references.get(name);
  if (!reference) {
    reference = { kinds: new Set(), symbols: new Set(), files: [] };
    usage.references.set(name, reference);
  }
  reference.kinds.add(kind);
  for (const symbol of symbols) reference.symbols.add(symbol);
  if (reference.files.length < MAX_EVIDENCE_FILES && !reference.files.includes(file)) {
    reference.files.push(file);
  }
}

function addMention(usage: PackageUsage, name: string, file: string): void {
  const files = usage.mentions.get(name) ?? [];
  if (files.length < MAX_EVIDENCE_FILES && !files.includes(file)) files.push(file);
  usage.mentions.set(name, files);
}

/** Names in `import { a as b, default as c, "string name" as d }`. */
function importedSymbols(specifiers: unknown): string[] {
  if (!Array.isArray(specifiers)) return [];
  const symbols: string[] = [];
  for (const specifier of specifiers) {
    if (!isNode(specifier)) continue;
    if (specifier.type === "ImportDefaultSpecifier") symbols.push("default");
    else if (specifier.type === "ImportNamespaceSpecifier") symbols.push("*");
    else if (specifier.type === "ImportSpecifier") {
      const imported = specifier.imported as { name?: string; value?: string } | undefined;
      symbols.push(imported?.name ?? imported?.value ?? "*");
    }
  }
  return symbols;
}

/** Keys of `const { a, b: c, ...rest } = require("x")`; `*` when the pattern takes everything. */
function patternSymbols(pattern: unknown): string[] {
  if (!isNode(pattern) || pattern.type !== "ObjectPattern") return ["*"];
  const symbols: string[] = [];
  for (const property of (pattern.properties as unknown[] | undefined) ?? []) {
    if (!isNode(property) || property.type !== "Property") return ["*"];
    const key = property.key as { name?: string; value?: string } | undefined;
    const name = key?.name ?? key?.value;
    if (property.computed || !name) return ["*"];
    symbols.push(name);
  }
  return symbols.length > 0 ? symbols : ["*"];
}

function propertyName(member: AstNode): string | undefined {
  const property = member.property as { name?: string; value?: string } | undefined;
  if (member.computed && !property?.value) return undefined;
  return property?.name ?? property?.value;
}

const isRequireCall = (node: unknown): node is AstNode =>
  isNode(node) &&
  node.type === "CallExpression" &&
  isNode(node.callee) &&
  node.callee.type === "Identifier" &&
  node.callee.name === "require";

const isRequireResolve = (callee: unknown): boolean =>
  isNode(callee) &&
  callee.type === "MemberExpression" &&
  isNode(callee.object) &&
  callee.object.type === "Identifier" &&
  callee.object.name === "require" &&
  propertyName(callee) === "resolve";

const isImportMetaResolve = (callee: unknown): boolean =>
  isNode(callee) &&
  callee.type === "MemberExpression" &&
  isNode(callee.object) &&
  callee.object.type === "MetaProperty" &&
  propertyName(callee) === "resolve";

/**
 * Parse one JavaScript or TypeScript file and record every way it can name a dependency. The
 * `interesting` set is the declared dependency names, so only those strings are kept as mentions.
 */
export function scanSource(
  usage: PackageUsage,
  path: string,
  content: string,
  interesting: ReadonlySet<string>,
  filename: string = path,
): void {
  let program: AstNode;
  let failed = false;
  try {
    const result = parseSync(filename, content);
    failed = result.errors.some((error) => (error.severity as unknown) === "Error");
    program = result.program as unknown as AstNode;
  } catch {
    usage.unparsedFiles.push(path);
    textMentions(usage, path, content, interesting);
    return;
  }
  if (failed) {
    // A partial tree can miss imports, so also search the raw text.
    usage.unparsedFiles.push(path);
    textMentions(usage, path, content, interesting);
  }

  const scan: SourceScan = { usage, path, interesting, handled: new WeakSet(), dynamic: false };
  visitSource(program, scan);

  if (scan.dynamic) usage.dynamicLoadFiles.push(path);

  // `/// <reference types="x" />` and the JSX pragma live in comments, which the tree does not hold.
  for (const match of content.matchAll(/\/\/\/\s*<reference\s+types\s*=\s*["']([^"']+)["']/g)) {
    if (match[1]) addReference(usage, match[1], "reference", ["*"], path);
  }
  for (const match of content.matchAll(/@jsxImportSource\s+(\S+)/g)) {
    if (match[1]) addReference(usage, match[1], "import", ["*"], path);
  }
}

interface SourceScan {
  usage: PackageUsage;
  path: string;
  interesting: ReadonlySet<string>;
  /** Call nodes whose symbols were read from their parent, so the generic visit skips them. */
  handled: WeakSet<object>;
  /** The file loads a module by a name only known at run time. */
  dynamic: boolean;
}

function visitSource(node: unknown, scan: SourceScan): void {
  if (Array.isArray(node)) {
    for (const child of node) visitSource(child, scan);
    return;
  }
  if (!isNode(node)) return;

  recordNode(node, scan);

  for (const key of Object.keys(node)) {
    if (key === "parent" || key === "start" || key === "end") continue;
    const value = node[key];
    if (value && typeof value === "object") visitSource(value, scan);
  }
}

function recordNode(node: AstNode, scan: SourceScan): void {
  switch (node.type) {
    case "ImportDeclaration": {
      recordImport(node, scan);
      break;
    }
    case "ExportAllDeclaration":
    case "ExportNamedDeclaration": {
      recordReExport(node, scan);
      break;
    }
    case "TSImportEqualsDeclaration": {
      const reference = node.moduleReference as AstNode | undefined;
      const specifier = staticSpecifier(reference?.expression);
      if (specifier !== undefined) addReference(scan.usage, specifier, "require", ["*"], scan.path);
      break;
    }
    case "TSImportType": {
      const specifier = staticSpecifier(node.source ?? node.argument);
      if (specifier !== undefined) {
        addReference(scan.usage, specifier, "type-import", ["*"], scan.path);
      }
      break;
    }
    case "ImportExpression": {
      if (!scan.handled.has(node)) recordDynamicImport(node, scan);
      break;
    }
    case "VariableDeclarator": {
      recordDeclaratorLoad(node, scan);
      break;
    }
    case "MemberExpression": {
      // require("x").thing
      if (isRequireCall(node.object)) {
        loadSymbols(scan, node.object, "require", [propertyName(node) ?? "*"]);
      }
      break;
    }
    case "CallExpression": {
      recordCall(node, scan);
      break;
    }
    case "Literal": {
      recordMention(node, scan);
      break;
    }
    default: {
      break;
    }
  }
}

function loadSymbols(
  scan: SourceScan,
  call: AstNode,
  kind: ReferenceKind,
  symbols: string[],
): void {
  scan.handled.add(call);
  const specifier = staticSpecifier((call.arguments as unknown[] | undefined)?.[0] ?? call.source);
  if (specifier === undefined) return;
  addReference(scan.usage, specifier, kind, symbols, scan.path);
}

function recordImport(node: AstNode, scan: SourceScan): void {
  const specifier = staticSpecifier(node.source);
  if (specifier === undefined) return;
  const typeOnly = node.importKind === "type";
  addReference(
    scan.usage,
    specifier,
    typeOnly ? "type-import" : "import",
    importedSymbols(node.specifiers),
    scan.path,
  );
}

function recordReExport(node: AstNode, scan: SourceScan): void {
  const specifier = staticSpecifier(node.source);
  if (specifier === undefined) return;
  const names =
    node.type === "ExportAllDeclaration"
      ? ["*"]
      : (
          (node.specifiers as { local?: { name?: string; value?: string } }[] | undefined) ?? []
        ).map((entry) => entry.local?.name ?? entry.local?.value ?? "*");
  addReference(
    scan.usage,
    specifier,
    node.exportKind === "type" ? "type-import" : "import",
    names,
    scan.path,
  );
}

function recordDynamicImport(node: AstNode, scan: SourceScan): void {
  const specifier = staticSpecifier(node.source);
  if (specifier === undefined) {
    if (!looksRelative(node.source)) scan.dynamic = true;
  } else {
    addReference(scan.usage, specifier, "dynamic-import", ["*"], scan.path);
  }
}

/** const { a } = require("x"), const x = require("x"), const { a } = await import("x") */
function recordDeclaratorLoad(node: AstNode, scan: SourceScan): void {
  const init =
    isNode(node.init) && node.init.type === "AwaitExpression" ? node.init.argument : node.init;
  if (isRequireCall(init)) {
    loadSymbols(scan, init, "require", patternSymbols(node.id));
  } else if (isNode(init) && init.type === "ImportExpression") {
    scan.handled.add(init);
    const specifier = staticSpecifier(init.source);
    if (specifier !== undefined) {
      addReference(scan.usage, specifier, "dynamic-import", patternSymbols(node.id), scan.path);
    } else if (!looksRelative(init.source)) {
      scan.dynamic = true;
    }
  }
}

function recordCall(node: AstNode, scan: SourceScan): void {
  const kind = isRequireCall(node) && !scan.handled.has(node) ? "require" : undefined;
  const resolves = isRequireResolve(node.callee) || isImportMetaResolve(node.callee);
  if (kind === undefined && !resolves) return;
  const argument = (node.arguments as unknown[] | undefined)?.[0];
  const specifier = staticSpecifier(argument);
  if (specifier === undefined) {
    if (!looksRelative(argument)) scan.dynamic = true;
  } else {
    addReference(scan.usage, specifier, kind ?? "resolve", ["*"], scan.path);
  }
}

function recordMention(node: AstNode, scan: SourceScan): void {
  if (
    typeof node.value === "string" &&
    node.value.length < 214 &&
    isDependencySpecifier(node.value)
  ) {
    const name = toRootPackageName(node.value);
    if (scan.interesting.has(name)) addMention(scan.usage, name, scan.path);
  }
}

/** Any quoted occurrence of a declared package name in raw text. */
export function textMentions(
  usage: PackageUsage,
  path: string,
  text: string,
  interesting: ReadonlySet<string>,
): void {
  for (const name of interesting) {
    if (!text.includes(name)) continue;
    const escaped = name.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
    if (new RegExp(`["'\`]${escaped}(?:["'\`/@]|$)`).test(text)) addMention(usage, name, path);
  }
}

/** Word-like tokens of a config, CI or script text, normalised the way a shell or loader would read them. */
export function tokensOf(text: string): string[] {
  const tokens = new Set<string>();
  for (const raw of text.match(/[@\w.~/:+-]+/g) ?? []) {
    let token = raw
      .replace(/^(\.\/)?(node_modules\/(\.bin\/)?)+/, "")
      .replaceAll(/^[.:+-]+|[.:+-]+$/g, "");
    if (token.startsWith("plugin:") || token.startsWith("npm:")) {
      token = token.slice(token.indexOf(":") + 1);
    }
    if (!token || /^[./]/.test(token) || token.length > 214) continue;
    tokens.add(token);
    // npx name@version
    const at = token.lastIndexOf("@");
    if (at > 0) tokens.add(token.slice(0, at));
  }
  return [...tokens];
}

/** Scan every file of one package directory into `usage`. */
export function scanPackage(
  packageDir: string,
  interesting: ReadonlySet<string>,
  options: { excludeDirectories?: ReadonlySet<string>; gitignoreRoots?: readonly string[] } = {},
  into: PackageUsage = emptyUsage(),
): { usage: PackageUsage; files: PackageFiles } {
  const files = collectPackageFiles(packageDir, options);
  for (const skipped of files.skipped) into.unparsedFiles.push(`${skipped} (too large to read)`);

  for (const file of files.files) {
    const text = readText(file.absolute);
    if (text === undefined) {
      into.unparsedFiles.push(file.path);
      continue;
    }
    if (file.role === "source" || file.parse) {
      into.sourceFiles += file.role === "source" ? 1 : 0;
      if (file.parse) scanSource(into, file.path, text, interesting, file.absolute);
    } else if (file.role === "template") {
      into.sourceFiles += 1;
      textMentions(into, file.path, text, interesting);
    }
    if (file.role === "script") into.sourceFiles += 1;
    if (file.role === "config" || file.role === "script") {
      into.configFiles += 1;
      for (const token of tokensOf(text)) {
        if (!into.tokens.has(token)) into.tokens.set(token, file.path);
      }
    }
  }
  return { usage: into, files };
}
