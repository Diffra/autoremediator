/**
 * Reads one source file into a `UsageIndex`: first where the package comes in and which local
 * names it is bound to, then every use of those names. Anything that cannot be followed is
 * recorded as opaque rather than dropped.
 */
import { lineOf, lineStarts, parseSource, propertyName, walk, type AstNode } from "./ast.js";
import type { CallSite, CallSiteKind } from "./types.js";
import type { UsageIndex } from "./usage-index.js";

const MAX_SITES_PER_KEY = 200;

interface Binding {
  specifier: string;
  mode: "named" | "object";
  /** Export name for a named binding. */
  name?: string;
}

/** What reading one file keeps: the index being filled, and the helpers that write to it. */
interface Scan {
  index: UsageIndex;
  bindings: Map<string, Binding>;
  usesPackage: boolean;
  site(node: AstNode, kind: CallSiteKind, extra?: Partial<CallSite>): CallSite;
  once(key: string): boolean;
  useExport(specifier: string, name: string, entry: CallSite): void;
  markOpaque(specifier: string, entry: CallSite): void;
  sourceSpecifier(value: unknown): string | undefined;
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const list = map.get(key);
  if (!list) map.set(key, [value]);
  else if (list.length < MAX_SITES_PER_KEY) list.push(value);
}

/** The value under `key`, created on first use. */
function getOrCreate<K, V>(map: Map<K, V>, key: K, create: () => V): V {
  let found = map.get(key);
  if (!found) {
    found = create();
    map.set(key, found);
  }
  return found;
}

/** Map an import source to `pkg` or `pkg/sub`, or undefined when it is another package. */
function specifierOfSource(source: string, packageName: string): string | undefined {
  if (source === packageName) return packageName;
  if (!source.startsWith(`${packageName}/`)) return undefined;
  const rest = source
    .slice(packageName.length + 1)
    .replace(/\.[cm]?js$/, "")
    .replace(/\/index$/, "");
  return rest === "" ? packageName : `${packageName}/${rest}`;
}

function literalString(node: unknown): string | undefined {
  const candidate = node as AstNode | undefined;
  return candidate?.type === "Literal" && typeof candidate.value === "string"
    ? candidate.value
    : undefined;
}

/** The module specifier of `require("x")` / `import("x")`, if the node is one. */
function loadSpecifier(node: AstNode): string | undefined {
  if (node.type === "ImportExpression") return literalString(node.source);
  if (node.type !== "CallExpression") return undefined;
  const callee = node.callee as AstNode | undefined;
  if (callee?.type !== "Identifier" || callee.name !== "require") return undefined;
  return literalString((node.arguments as unknown[] | undefined)?.[0]);
}

const TRANSPARENT = new Set([
  "AwaitExpression",
  "ChainExpression",
  "TSAsExpression",
  "TSNonNullExpression",
  "TSSatisfiesExpression",
]);

function argCountOf(call: AstNode): number | undefined {
  const args = (call.arguments as AstNode[] | undefined) ?? [];
  return args.some((argument) => argument.type === "SpreadElement") ? undefined : args.length;
}

/** The local name a destructured property binds (`{ a }`, `{ a = 1 }`), or undefined for a pattern. */
function boundLocalName(target: AstNode | undefined): string | undefined {
  if (target?.type === "Identifier") {
    return String(target.name);
  }
  const left =
    target?.type === "AssignmentPattern" ? (target.left as AstNode | undefined) : undefined;
  return left?.type === "Identifier" ? String(left.name) : undefined;
}

function createScan(index: UsageIndex, file: string, code: string): Scan {
  const starts = lineStarts(code);
  const lines = code.split("\n");
  const dedupe = new Set<string>();
  const once = (key: string): boolean => {
    if (dedupe.has(key)) return false;
    dedupe.add(key);
    return true;
  };
  return {
    index,
    bindings: new Map(),
    usesPackage: false,
    once,
    site(node, kind, extra = {}) {
      const line = lineOf(starts, node.start);
      return {
        file,
        line,
        kind,
        text: (lines[line - 1] ?? "").trim().slice(0, 160),
        confidence: "exact",
        ...extra,
      };
    },
    useExport(specifier, name, entry) {
      if (!once(`${specifier}|${name}|${entry.line}|${entry.kind}`)) return;
      push(
        getOrCreate(index.exportUses, specifier, () => new Map()),
        name,
        entry,
      );
    },
    markOpaque(specifier, entry) {
      if (once(`o|${specifier}|${entry.line}`)) push(index.opaque, specifier, entry);
    },
    sourceSpecifier(value) {
      return typeof value === "string" ? specifierOfSource(value, index.packageName) : undefined;
    },
  };
}

/** Records the package as used by this file at `specifier`. */
function noteSpecifier(scan: Scan, specifier: string): void {
  scan.usesPackage = true;
  scan.index.specifiers.add(specifier);
}

/** `import ... from "pkg"`. Returns false: nothing inside an import needs visiting. */
function readImport(scan: Scan, node: AstNode): boolean {
  const specifier = scan.sourceSpecifier((node.source as { value?: unknown } | undefined)?.value);
  if (!specifier) return true;
  noteSpecifier(scan, specifier);
  push(scan.index.importSites, specifier, scan.site(node, "import"));
  for (const item of (node.specifiers as AstNode[] | undefined) ?? []) {
    const local = (item.local as { name?: string } | undefined)?.name;
    if (!local) continue;
    if (item.type !== "ImportSpecifier") {
      scan.bindings.set(local, { specifier, mode: "object" });
      continue;
    }
    const imported = item.imported as { name?: string; value?: string } | undefined;
    const name = imported?.name ?? imported?.value ?? local;
    if (name === "default") {
      scan.bindings.set(local, { specifier, mode: "object" });
    } else {
      scan.bindings.set(local, { specifier, mode: "named", name });
      scan.useExport(specifier, name, scan.site(item, "import"));
    }
  }
  return false;
}

/** `export ... from "pkg"`. */
function readReexport(scan: Scan, node: AstNode): boolean {
  const source = (node.source as { value?: unknown } | null | undefined)?.value;
  const specifier = scan.sourceSpecifier(source);
  if (!specifier) return true;
  noteSpecifier(scan, specifier);
  push(scan.index.importSites, specifier, scan.site(node, "reexport"));
  if (node.type === "ExportAllDeclaration") {
    scan.markOpaque(specifier, scan.site(node, "reexport"));
    return false;
  }
  for (const item of (node.specifiers as AstNode[] | undefined) ?? []) {
    const local = item.local as { name?: string; value?: string } | undefined;
    const name = local?.name ?? local?.value;
    if (name) scan.useExport(specifier, name, scan.site(item, "reexport"));
  }
  return false;
}

/** Climbs through `await`, `as` and optional chains to where a loaded module goes. */
function destinationOf(
  node: AstNode,
  ancestors: readonly AstNode[],
): { value: AstNode; parent: AstNode | undefined; container: AstNode | undefined } {
  let value: AstNode = node;
  let parentIndex = ancestors.length - 1;
  for (
    let current = ancestors[parentIndex];
    current && TRANSPARENT.has(current.type);
    current = ancestors[parentIndex]
  ) {
    value = current;
    parentIndex--;
  }
  return { value, parent: ancestors[parentIndex], container: ancestors[parentIndex - 1] };
}

/** `const x = require("p")` and `const { a, b } = require("p")`. */
function readDeclarator(scan: Scan, declarator: AstNode, specifier: string, loadSite: CallSite) {
  const id = declarator.id as AstNode | undefined;
  if (id?.type === "Identifier") {
    scan.bindings.set(String(id.name), { specifier, mode: "object" });
    return;
  }
  if (id?.type !== "ObjectPattern") {
    scan.markOpaque(specifier, loadSite);
    return;
  }
  for (const property of (id.properties as AstNode[] | undefined) ?? []) {
    if (property.type !== "Property") {
      scan.markOpaque(specifier, loadSite);
      continue;
    }
    const name = propertyName(property.key, property.computed === true);
    if (name === undefined) {
      scan.markOpaque(specifier, loadSite);
      continue;
    }
    scan.useExport(specifier, name, scan.site(property, "reference"));
    const local = boundLocalName(property.value as AstNode | undefined);
    if (local) scan.bindings.set(local, { specifier, mode: "named", name });
  }
}

/** `require("p").x`, `require("p").x(...)`, `const x = require("p").x`. */
function readLoadedMember(
  scan: Scan,
  load: { node: AstNode; specifier: string; loadSite: CallSite },
  member: AstNode,
  container: AstNode | undefined,
): void {
  const { node, specifier, loadSite } = load;
  const name = propertyName(member.property, member.computed === true);
  if (name === undefined || (node.type === "ImportExpression" && name === "then")) {
    scan.markOpaque(specifier, loadSite);
    return;
  }
  if (
    container?.type === "VariableDeclarator" &&
    container.init === member &&
    (container.id as AstNode | undefined)?.type === "Identifier"
  ) {
    scan.bindings.set(String((container.id as AstNode).name), { specifier, mode: "named", name });
  }
  if (container?.type === "CallExpression" && container.callee === member) {
    scan.useExport(specifier, name, scan.site(member, "call", { argCount: argCountOf(container) }));
  } else {
    scan.useExport(specifier, name, scan.site(member, "member"));
  }
}

/** A `require()` or `import()` of the package: follow the value to where it ends up. */
function readLoad(scan: Scan, node: AstNode, specifier: string, ancestors: readonly AstNode[]) {
  noteSpecifier(scan, specifier);
  const loadSite = scan.site(node, node.type === "ImportExpression" ? "dynamic-import" : "require");
  push(scan.index.requireSites, specifier, loadSite);

  const { value, parent, container } = destinationOf(node, ancestors);
  if (!parent) return;
  if (parent.type === "VariableDeclarator" && parent.init === value) {
    readDeclarator(scan, parent, specifier, loadSite);
  } else if (parent.type === "MemberExpression" && parent.object === value) {
    readLoadedMember(scan, { node, specifier, loadSite }, parent, container);
  } else if (parent.type === "CallExpression" && parent.callee === value) {
    const call = scan.site(parent, "call", { argCount: argCountOf(parent) });
    scan.useExport(specifier, "default", call);
  } else if (parent.type === "ExpressionStatement") {
    // A bare `require("p")` for its side effects uses nothing.
  } else if (
    parent.type === "AssignmentExpression" &&
    parent.right === value &&
    (parent.left as AstNode | undefined)?.type === "Identifier"
  ) {
    scan.bindings.set(String((parent.left as AstNode).name), { specifier, mode: "object" });
  } else {
    scan.markOpaque(specifier, loadSite);
  }
}

/** Pass 1: where the package comes in, and the local names it is bound to. */
function readEntry(scan: Scan, node: AstNode, ancestors: readonly AstNode[]): boolean {
  if (node.type === "ImportDeclaration") return readImport(scan, node);
  if (node.type === "ExportNamedDeclaration" || node.type === "ExportAllDeclaration") {
    return readReexport(scan, node);
  }
  const loaded = loadSpecifier(node);
  const specifier =
    loaded === undefined ? undefined : specifierOfSource(loaded, scan.index.packageName);
  if (specifier !== undefined) readLoad(scan, node, specifier, ancestors);
  return true;
}

/** Whether an identifier occurrence only declares or names something, so it is not a use. */
function isNotAUse(node: AstNode, parent: AstNode): boolean {
  if (parent.type === "VariableDeclarator" && parent.id === node) return true;
  if (parent.type === "MemberExpression" && parent.property === node && parent.computed !== true) {
    return true;
  }
  const keyed =
    parent.type === "Property" ||
    parent.type === "MethodDefinition" ||
    parent.type === "PropertyDefinition" ||
    parent.type === "TSPropertySignature";
  if (keyed && parent.key === node && parent.computed !== true) return true;
  if (
    (parent.type === "FunctionDeclaration" || parent.type === "ClassDeclaration") &&
    parent.id === node
  ) {
    return true;
  }
  return (
    parent.type === "ImportSpecifier" ||
    parent.type === "ImportDefaultSpecifier" ||
    parent.type === "ImportNamespaceSpecifier"
  );
}

/** `.name` accesses on anything that is not the package's module object, for class members. */
function noteMemberName(scan: Scan, node: AstNode): void {
  const name = propertyName(node.property, false);
  const object = node.object as AstNode | undefined;
  const bound = object?.type === "Identifier" ? scan.bindings.get(String(object.name)) : undefined;
  if (name === undefined || bound?.mode === "object") return;
  const entry = scan.site(node, "member", { confidence: "name-match" });
  if (scan.once(`m|${name}|${entry.line}`)) push(scan.index.memberNameUses, name, entry);
}

/** `bound.member`, `bound.member()`, `new bound.member()`. */
function readBoundMember(
  scan: Scan,
  use: { node: AstNode; parent: AstNode; grand: AstNode | undefined },
  binding: Binding,
  exportName: string,
): void {
  const { node, parent, grand } = use;
  const member =
    parent.computed === true
      ? literalString(parent.property)
      : propertyName(parent.property, false);
  if (member === undefined) {
    if (binding.mode === "object") scan.markOpaque(binding.specifier, scan.site(node, "reference"));
    else scan.useExport(binding.specifier, exportName, scan.site(node, "reference"));
    return;
  }
  const isCall = grand?.type === "CallExpression" && grand.callee === parent;
  const isNew = grand?.type === "NewExpression" && grand.callee === parent;
  let kind: CallSiteKind = "member";
  if (isCall) {
    kind = "call";
  } else if (isNew) {
    kind = "new";
  }
  const extra = isCall && grand ? { argCount: argCountOf(grand) } : {};
  if (binding.mode === "object") {
    scan.useExport(binding.specifier, member, scan.site(parent, kind, extra));
    return;
  }
  scan.useExport(binding.specifier, exportName, scan.site(node, "reference"));
  const byExport = getOrCreate(scan.index.staticMemberUses, binding.specifier, () => new Map());
  const byMember = getOrCreate(byExport, exportName, () => new Map());
  push(byMember, member, scan.site(parent, kind, extra));
}

/** Pass 2: one occurrence of a name the package is bound to. */
function readBoundUse(
  scan: Scan,
  node: AstNode,
  parent: AstNode,
  ancestors: readonly AstNode[],
): void {
  const binding = scan.bindings.get(String(node.name));
  if (!binding || isNotAUse(node, parent)) return;
  const exportName = binding.mode === "named" ? (binding.name ?? "default") : "default";
  const record = (kind: CallSiteKind, extra: Partial<CallSite> = {}): void => {
    scan.useExport(binding.specifier, exportName, scan.site(node, kind, extra));
  };

  if (parent.type === "MemberExpression" && parent.object === node) {
    readBoundMember(scan, { node, parent, grand: ancestors.at(-2) }, binding, exportName);
  } else if (parent.type === "CallExpression" && parent.callee === node) {
    record("call", { argCount: argCountOf(parent) });
  } else if (parent.type === "NewExpression" && parent.callee === node) {
    record("new", { argCount: argCountOf(parent) });
  } else if (parent.type === "TSTypeReference" && parent.typeName === node) {
    record("type-reference");
  } else if (
    parent.type === "TSQualifiedName" &&
    parent.left === node &&
    binding.mode === "object"
  ) {
    const right = (parent.right as { name?: string } | undefined)?.name;
    if (right) scan.useExport(binding.specifier, right, scan.site(parent, "type-reference"));
  } else if (binding.mode === "object") {
    scan.markOpaque(binding.specifier, scan.site(node, "reference"));
  } else {
    record("reference");
  }
}

/** Reads one file's uses of the package into `index`. */
export function scanFile(index: UsageIndex, file: string, code: string): void {
  const program = parseSource(file, code);
  if (!program) return;
  const scan = createScan(index, file, code);

  walk(program, (node, _parent, ancestors) => readEntry(scan, node, ancestors));
  if (!scan.usesPackage) return;
  index.filesUsingPackage++;

  walk(program, (node, parent, ancestors) => {
    if (node.type === "ImportDeclaration") return false;
    if (node.type === "MemberExpression" && node.computed !== true) noteMemberName(scan, node);
    if (node.type === "Identifier" && parent) readBoundUse(scan, node, parent, ancestors);
    return true;
  });
}
