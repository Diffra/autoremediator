/**
 * JavaScript export analysis: what a module file exports (ESM and CommonJS, re-exports, classes and
 * their members) and a canonical fingerprint of each exported definition, so two versions of a
 * package can be compared by what the code does rather than how it is formatted.
 */
import { canonicalForm, nameOfNode, parseSource, propertyName, walk, type AstNode } from "./ast.js";
import {
  collectLocals,
  identName,
  identifierNames,
  isClassNode,
  isFunctionNode,
  isModuleExports,
  isVoidZero,
  membersOfClass,
  paramsOfFunction,
  placeholder,
  requireSpecifier,
  type DefinitionKind,
  type LocalDef,
} from "./js-locals.js";
import type { ExportBinding, ModuleInfo, ReExport } from "./js-module-types.js";

export type { DefinitionKind, LocalDef } from "./js-locals.js";
export type { ExportBinding, ModuleInfo, ReExport } from "./js-module-types.js";

/** What reading one module collects as it goes. */
interface ModuleScan {
  locals: Map<string, LocalDef>;
  exports: Map<string, ExportBinding>;
  reexports: ReExport[];
  relativeImports: Set<string>;
  /** `const x = require("./x")` and `import * as x from "./x"`: local name -> module. */
  requireAliases: Map<string, string>;
  moduleExportsLocal?: string;
  moduleExportsRequire?: string;
}

function definitionKindOf(expression: AstNode): DefinitionKind {
  if (isFunctionNode(expression)) {
    return "function";
  }
  return isClassNode(expression) ? "class" : "value";
}

function moduleBinding(exportName: string, moduleRef: string): ExportBinding {
  return {
    name: exportName,
    kind: "module",
    fingerprint: `module:${moduleRef}`,
    refs: new Set(),
    tokens: new Set(),
    nodeCount: 1,
    moduleRef,
  };
}

function bindingFromLocal(
  scan: ModuleScan,
  exportName: string,
  localName: string,
): ExportBinding | undefined {
  const local = scan.locals.get(localName);
  if (local) {
    return {
      name: exportName,
      kind: local.kind,
      fingerprint: local.fingerprint,
      local: localName,
      refs: local.refs,
      tokens: local.tokens,
      nodeCount: local.nodeCount,
      params: local.params,
      members: local.members,
    };
  }
  const moduleRef = scan.requireAliases.get(localName);
  return moduleRef ? moduleBinding(exportName, moduleRef) : undefined;
}

function bindingFromExpression(
  scan: ModuleScan,
  exportName: string,
  expression: AstNode,
): ExportBinding {
  const identifier = identName(expression);
  if (identifier) {
    const fromLocal = bindingFromLocal(scan, exportName, identifier);
    if (fromLocal) return fromLocal;
  }
  const required = requireSpecifier(expression);
  if (required) return moduleBinding(exportName, required);
  const form = canonicalForm(expression, placeholder);
  return {
    name: exportName,
    kind: definitionKindOf(expression),
    fingerprint: form.fingerprint,
    refs: identifierNames(expression),
    tokens: form.tokens,
    nodeCount: form.nodeCount,
    params: isFunctionNode(expression) ? paramsOfFunction(expression) : undefined,
    members: isClassNode(expression) ? membersOfClass(expression) : undefined,
  };
}

function setExport(scan: ModuleScan, name: string, binding: ExportBinding): void {
  if (name === "__esModule") return;
  scan.exports.set(name, binding);
}

function noteImport(scan: ModuleScan, specifier: string | undefined): void {
  if (specifier?.startsWith(".")) scan.relativeImports.add(specifier);
}

/** `const x = require("./x")` aliases, needed to resolve `module.exports = x`, and the imports. */
function collectAliases(scan: ModuleScan, program: AstNode): void {
  walk(program, (node) => {
    if (node.type === "VariableDeclarator") {
      const name = identName(node.id);
      const specifier = requireSpecifier(node.init as AstNode | undefined);
      if (name && specifier) scan.requireAliases.set(name, specifier);
    }
    if (node.type === "ImportDeclaration") {
      const source = (node.source as { value?: string } | undefined)?.value;
      noteImport(scan, source);
      if (source) {
        for (const specifier of (node.specifiers as AstNode[] | undefined) ?? []) {
          const local = identName(specifier.local);
          if (local && specifier.type === "ImportNamespaceSpecifier") {
            scan.requireAliases.set(local, source);
          }
        }
      }
    }
    const required = requireSpecifier(node);
    if (required) noteImport(scan, required);
  });
}

/** `module.exports = { a, b: fn, ...require("./c") }`. */
function readExportedObject(scan: ModuleScan, object: AstNode): void {
  for (const property of (object.properties as AstNode[] | undefined) ?? []) {
    if (property.type === "SpreadElement") {
      const spread = requireSpecifier(property.argument as AstNode | undefined);
      if (spread) {
        scan.reexports.push({ source: spread, kind: "all", names: [] });
        noteImport(scan, spread);
      }
      continue;
    }
    const name = propertyName(property.key, property.computed === true);
    const value = property.value as AstNode | undefined;
    if (name !== undefined && value) {
      setExport(scan, name, bindingFromExpression(scan, name, value));
    }
  }
}

/** `module.exports = <right>`. */
function readModuleExportsAssignment(scan: ModuleScan, right: AstNode): void {
  const required = requireSpecifier(right);
  if (required) {
    scan.moduleExportsRequire = required;
    return;
  }
  if (right.type === "ObjectExpression") {
    readExportedObject(scan, right);
    return;
  }
  const alias = identName(right);
  if (alias) {
    // An alias built elsewhere (`module.exports = _`): its properties are the exports.
    scan.moduleExportsLocal = alias;
    if (scan.locals.has(alias) || scan.requireAliases.has(alias)) {
      const binding = bindingFromLocal(scan, "module.exports", alias);
      if (binding) setExport(scan, "module.exports", binding);
    }
    return;
  }
  setExport(scan, "module.exports", bindingFromExpression(scan, "module.exports", right));
}

/** `exports.name = <right>`, `module.exports.name = <right>`, `<moduleExportsAlias>.name = ...`. */
function readExportsMember(scan: ModuleScan, left: AstNode, right: AstNode): void {
  if (left.type !== "MemberExpression") return;
  const target = left.object as AstNode | undefined;
  const targetName = identName(target);
  const isExportsObject =
    targetName === "exports" ||
    isModuleExports(target) ||
    (scan.moduleExportsLocal !== undefined && targetName === scan.moduleExportsLocal);
  if (!isExportsObject) return;
  const name = propertyName(left.property, left.computed === true);
  if (name === undefined) return;
  setExport(scan, name, bindingFromExpression(scan, name, right));
}

function readAssignment(scan: ModuleScan, node: AstNode): void {
  const left = node.left as AstNode | undefined;
  if (!left || node.operator !== "=") return;
  let right = node.right as AstNode | undefined;
  while (right?.type === "AssignmentExpression") right = right.right as AstNode | undefined;
  if (!right || isVoidZero(right)) return;
  if (isModuleExports(left)) readModuleExportsAssignment(scan, right);
  else readExportsMember(scan, left, right);
}

/** `export function f() {}`, `export const a = 1, b = 2`. */
function readExportedDeclaration(scan: ModuleScan, declaration: AstNode): void {
  if (
    (declaration.type === "FunctionDeclaration" || declaration.type === "ClassDeclaration") &&
    declaration.id
  ) {
    const name = identName(declaration.id);
    const binding = name ? bindingFromLocal(scan, name, name) : undefined;
    if (name && binding) scan.exports.set(name, binding);
  } else if (declaration.type === "VariableDeclaration") {
    for (const declarator of (declaration.declarations as AstNode[] | undefined) ?? []) {
      const name = identName(declarator.id);
      if (!name) continue;
      const binding =
        bindingFromLocal(scan, name, name) ??
        (declarator.init
          ? bindingFromExpression(scan, name, declarator.init as AstNode)
          : undefined);
      if (binding) scan.exports.set(name, binding);
    }
  }
}

/** `export { a as b }`, `export { a } from "./x"` and `export <declaration>`. */
function readExportNamed(scan: ModuleScan, statement: AstNode): void {
  const source = (statement.source as { value?: string } | null)?.value;
  const declaration = statement.declaration as AstNode | null;
  if (declaration) {
    readExportedDeclaration(scan, declaration);
    return;
  }
  const specifiers = (statement.specifiers as AstNode[] | undefined) ?? [];
  if (source) {
    noteImport(scan, source);
    scan.reexports.push({
      source,
      kind: "named",
      names: specifiers.map((specifier) => ({
        exported: nameOfNode(specifier.exported) ?? "",
        imported: nameOfNode(specifier.local) ?? "",
      })),
    });
    return;
  }
  for (const specifier of specifiers) {
    const exported = nameOfNode(specifier.exported) ?? "";
    const local = nameOfNode(specifier.local) ?? "";
    const binding = bindingFromLocal(scan, exported, local);
    if (binding) scan.exports.set(exported, binding);
  }
}

/** `export * from "./x"` and `export * as ns from "./x"`. */
function readExportAll(scan: ModuleScan, statement: AstNode): void {
  const source = (statement.source as { value?: string } | undefined)?.value;
  if (!source) return;
  noteImport(scan, source);
  const exported = statement.exported as { name?: string; value?: string } | null;
  scan.reexports.push(
    exported
      ? { source, kind: "namespace", names: [], namespace: exported.name ?? exported.value }
      : { source, kind: "all", names: [] },
  );
}

function readExportDefault(scan: ModuleScan, statement: AstNode): void {
  const declaration = statement.declaration as AstNode | undefined;
  if (!declaration) return;
  const declaredName = declaration.id ? identName(declaration.id) : undefined;
  if (declaredName && scan.locals.has(declaredName)) {
    const binding = bindingFromLocal(scan, "default", declaredName);
    if (binding) scan.exports.set("default", binding);
  } else {
    scan.exports.set("default", bindingFromExpression(scan, "default", declaration));
  }
}

/** ESM declarations, in the order they appear. */
function readEsmExports(scan: ModuleScan, program: AstNode): void {
  for (const statement of (program.body as AstNode[] | undefined) ?? []) {
    if (statement.type === "ExportNamedDeclaration") readExportNamed(scan, statement);
    else if (statement.type === "ExportAllDeclaration") readExportAll(scan, statement);
    else if (statement.type === "ExportDefaultDeclaration") readExportDefault(scan, statement);
  }
}

/** `Object.defineProperty(exports, "name", { get() {...} })`, the form TypeScript emits. */
function readDefineProperty(scan: ModuleScan, callee: AstNode | undefined, args: AstNode[]): void {
  if (
    callee?.type !== "MemberExpression" ||
    identName(callee.object) !== "Object" ||
    propertyName(callee.property, false) !== "defineProperty" ||
    args.length < 3 ||
    !(identName(args[0]) === "exports" || isModuleExports(args[0])) ||
    args[1]?.type !== "Literal" ||
    typeof args[1].value !== "string"
  ) {
    return;
  }
  const name = args[1].value;
  const descriptor = args[2];
  if (name === "__esModule" || descriptor?.type !== "ObjectExpression") return;
  const properties = descriptor.properties as AstNode[];
  const named = (key: string) =>
    properties.find((property) => propertyName(property.key, property.computed === true) === key);
  const source = (named("get")?.value ?? named("value")?.value) as AstNode | undefined;
  if (!source) return;
  const form = canonicalForm(source, placeholder);
  scan.exports.set(name, {
    name,
    kind: "value",
    fingerprint: form.fingerprint,
    refs: identifierNames(source),
    tokens: form.tokens,
    nodeCount: form.nodeCount,
  });
}

/** `__exportStar(require("./x"), exports)` and `Object.defineProperty(exports, ...)`. */
function readCallExport(scan: ModuleScan, node: AstNode): void {
  const callee = node.callee as AstNode | undefined;
  const calleeName =
    identName(callee) ??
    (callee?.type === "MemberExpression"
      ? propertyName(callee.property, callee.computed === true)
      : undefined);
  const args = (node.arguments as AstNode[] | undefined) ?? [];
  if ((calleeName === "__exportStar" || calleeName === "__export") && args[0]) {
    const source = requireSpecifier(args[0]);
    if (source) {
      noteImport(scan, source);
      scan.reexports.push({ source, kind: "all", names: [] });
    }
  }
  readDefineProperty(scan, callee, args);
}

/** CommonJS: assignments anywhere (they are often inside a UMD wrapper). */
function readCommonJsExports(scan: ModuleScan, program: AstNode): AstNode[] {
  const assignments: AstNode[] = [];
  walk(program, (node) => {
    if (node.type === "AssignmentExpression") assignments.push(node);
    if (node.type === "CallExpression") readCallExport(scan, node);
  });
  for (const assignment of assignments) {
    if (isModuleExports(assignment.left)) readAssignment(scan, assignment);
  }
  for (const assignment of assignments) {
    if (!isModuleExports(assignment.left)) readAssignment(scan, assignment);
  }
  if (scan.moduleExportsRequire) {
    scan.reexports.push({
      source: scan.moduleExportsRequire,
      kind: "all",
      names: [],
      includeDefault: true,
    });
  }
  return assignments;
}

/** The object a plain `object.name = value` assignment writes to. */
function assignedTo(assignment: AstNode): string | undefined {
  const left = assignment.left as AstNode | undefined;
  if (left?.type !== "MemberExpression" || left.computed === true) return undefined;
  return identName(left.object);
}

/** UMD bundles such as lodash export a namespace function built up with `ns.name = fn`. */
function readNamespaceAssignments(scan: ModuleScan, assignments: AstNode[]): boolean {
  const counts = new Map<string, number>();
  for (const assignment of assignments) {
    const object = assignedTo(assignment);
    if (object) counts.set(object, (counts.get(object) ?? 0) + 1);
  }
  const [best] = [...counts].toSorted((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (!best || best[1] < 8) return false;
  for (const assignment of assignments) {
    if (assignedTo(assignment) !== best[0]) continue;
    const left = assignment.left as AstNode;
    const name = propertyName(left.property, false);
    const right = assignment.right as AstNode | undefined;
    if (name !== undefined && right) {
      scan.exports.set(name, bindingFromExpression(scan, name, right));
    }
  }
  return scan.exports.size > 0;
}

/** Analyse one module file; undefined when it cannot be parsed. */
export function analyzeModule(path: string, code: string): ModuleInfo | undefined {
  const program = parseSource(path, code);
  if (!program) return undefined;

  const scan: ModuleScan = {
    locals: collectLocals(program),
    exports: new Map(),
    reexports: [],
    relativeImports: new Set(),
    requireAliases: new Map(),
  };
  collectAliases(scan, program);
  readEsmExports(scan, program);
  const assignments = readCommonJsExports(scan, program);

  let discovery: ModuleInfo["discovery"] =
    scan.exports.size > 0 || scan.reexports.length > 0 ? "declared" : "none";
  if (discovery === "none" && readNamespaceAssignments(scan, assignments)) {
    discovery = "namespace-assignments";
  }

  return {
    path,
    fingerprint: canonicalForm(program).fingerprint,
    locals: scan.locals,
    exports: scan.exports,
    reexports: scan.reexports,
    relativeImports: [...scan.relativeImports].toSorted(),
    discovery,
  };
}
