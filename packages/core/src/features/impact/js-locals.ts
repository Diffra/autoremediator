/**
 * The definitions a JavaScript module declares (functions, classes and module-level values) with a
 * canonical fingerprint of each, and the small AST predicates the export analysis shares.
 */
import {
  canonicalForm,
  isNode,
  memberKindOfMethod,
  propertyName,
  walk,
  type AstNode,
} from "./ast.js";
import type { ClassMemberInfo, ParamInfo } from "./types.js";

export type DefinitionKind = "function" | "class" | "value";

export interface LocalDef {
  name: string;
  kind: DefinitionKind;
  /** Fingerprint of the definition with nested named definitions left out. */
  fingerprint: string;
  /** Identifier names mentioned in the definition. */
  refs: Set<string>;
  tokens: Set<string>;
  nodeCount: number;
  params?: ParamInfo[];
  members?: ClassMemberInfo[];
}

const FUNCTION_TYPES = new Set([
  "FunctionDeclaration",
  "FunctionExpression",
  "ArrowFunctionExpression",
  "TSDeclareFunction",
  "TSEmptyBodyFunctionExpression",
]);

export function isFunctionNode(node: AstNode | undefined): node is AstNode {
  return node !== undefined && FUNCTION_TYPES.has(node.type);
}

export function isClassNode(node: AstNode | undefined): node is AstNode {
  return (
    node !== undefined && (node.type === "ClassDeclaration" || node.type === "ClassExpression")
  );
}

export function identName(node: unknown): string | undefined {
  return isNode(node) && node.type === "Identifier" ? String(node.name) : undefined;
}

/** Parameters of a function node as `ParamInfo`s (JavaScript view: a default makes it optional). */
export function paramsOfFunction(fn: AstNode): ParamInfo[] {
  const params = (fn.params as unknown[] | undefined) ?? [];
  const result: ParamInfo[] = [];
  for (const [index, raw] of params.entries()) {
    if (!isNode(raw)) continue;
    if (raw.type === "AssignmentPattern") {
      result.push({ name: identName(raw.left) ?? `arg${index}`, optional: true, rest: false });
    } else if (raw.type === "RestElement") {
      result.push({ name: identName(raw.argument) ?? `arg${index}`, optional: true, rest: true });
    } else if (raw.type === "Identifier") {
      result.push({ name: String(raw.name), optional: raw.optional === true, rest: false });
    } else {
      result.push({ name: `arg${index}`, optional: false, rest: false });
    }
  }
  return result;
}

export function membersOfClass(cls: AstNode): ClassMemberInfo[] {
  const body = (cls.body as AstNode | undefined)?.body as unknown[] | undefined;
  const members: ClassMemberInfo[] = [];
  for (const item of body ?? []) {
    if (!isNode(item)) continue;
    if (item.type !== "MethodDefinition" && item.type !== "PropertyDefinition") continue;
    if (item.accessibility === "private") continue;
    const key = item.key as AstNode | undefined;
    if (key?.type === "PrivateIdentifier") continue;
    const name = propertyName(key, item.computed === true);
    if (name === undefined) continue;
    const isStatic = item.static === true;
    if (item.type === "MethodDefinition") {
      const value = item.value as AstNode | undefined;
      const kind = item.kind as string;
      members.push({
        name: kind === "constructor" ? "constructor" : name,
        static: isStatic,
        kind: memberKindOfMethod(kind),
        params: isFunctionNode(value) ? paramsOfFunction(value) : undefined,
        fingerprint: value ? canonicalForm(value).fingerprint : "",
      });
    } else {
      members.push({
        name,
        static: isStatic,
        kind: "field",
        fingerprint: item.value && isNode(item.value) ? canonicalForm(item.value).fingerprint : "",
      });
    }
  }
  return members;
}

export function requireSpecifier(node: AstNode | undefined): string | undefined {
  if (node?.type !== "CallExpression") return undefined;
  const callee = node.callee as AstNode | undefined;
  if (callee?.type !== "Identifier" || callee.name !== "require") return undefined;
  const first = (node.arguments as unknown[] | undefined)?.[0];
  return isNode(first) && first.type === "Literal" && typeof first.value === "string"
    ? first.value
    : undefined;
}

export function isModuleExports(node: unknown): boolean {
  return (
    isNode(node) &&
    node.type === "MemberExpression" &&
    identName(node.object) === "module" &&
    propertyName(node.property, node.computed === true) === "exports"
  );
}

export function isVoidZero(node: AstNode): boolean {
  return (
    (node.type === "UnaryExpression" && node.operator === "void") ||
    (node.type === "Identifier" && node.name === "undefined")
  );
}

export function identifierNames(root: AstNode): Set<string> {
  const names = new Set<string>();
  walk(root, (node) => {
    if (node.type === "Identifier") names.add(String(node.name));
  });
  return names;
}

function isNamedDefinition(node: AstNode): string | undefined {
  if ((node.type === "FunctionDeclaration" || node.type === "ClassDeclaration") && node.id) {
    return identName(node.id);
  }
  if (node.type === "VariableDeclarator") {
    const name = identName(node.id);
    const init = node.init as AstNode | undefined;
    if (name && init && (isFunctionNode(init) || isClassNode(init))) return name;
  }
  return undefined;
}

interface LocalAccumulator {
  kind: DefinitionKind;
  fingerprints: string[];
  refs: Set<string>;
  tokens: Set<string>;
  nodeCount: number;
  params?: ParamInfo[];
  members?: ClassMemberInfo[];
}

export function collectLocals(program: AstNode): Map<string, LocalDef> {
  const accumulators = new Map<string, LocalAccumulator>();
  const add = (name: string, root: AstNode, kind: DefinitionKind, definition?: AstNode): void => {
    const form = canonicalForm(root, placeholder);
    const existing = accumulators.get(name);
    const accumulator: LocalAccumulator = existing ?? {
      kind,
      fingerprints: [],
      refs: new Set(),
      tokens: new Set(),
      nodeCount: 0,
    };
    accumulator.fingerprints.push(form.fingerprint);
    for (const ref of identifierNames(root)) accumulator.refs.add(ref);
    for (const token of form.tokens) accumulator.tokens.add(token);
    accumulator.nodeCount += form.nodeCount;
    if (!existing) {
      if (isFunctionNode(definition)) accumulator.params = paramsOfFunction(definition);
      if (isClassNode(definition)) accumulator.members = membersOfClass(definition);
      accumulators.set(name, accumulator);
    }
  };

  walk(program, (node, _parent, ancestors) => {
    const named = isNamedDefinition(node);
    if (named !== undefined) {
      const definition =
        node.type === "VariableDeclarator" ? (node.init as AstNode | undefined) : node;
      add(named, node, isClassNode(definition) ? "class" : "function", definition);
      return;
    }
    if (node.type === "VariableDeclarator") {
      const name = identName(node.id);
      if (!name || !node.init || requireSpecifier(node.init as AstNode)) return;
      // Module-level values only: a `var index = -1` inside a function is not a definition worth
      // tracking, and would merge into one entry per name.
      const insideNamedDefinition = ancestors.some((ancestor) => isNamedDefinition(ancestor));
      if (!insideNamedDefinition) add(name, node, "value");
    }
  });

  const locals = new Map<string, LocalDef>();
  for (const [name, accumulator] of accumulators) {
    locals.set(name, {
      name,
      kind: accumulator.kind,
      fingerprint: accumulator.fingerprints.join("+"),
      refs: accumulator.refs,
      tokens: accumulator.tokens,
      nodeCount: accumulator.nodeCount,
      params: accumulator.params,
      members: accumulator.members,
    });
  }
  return locals;
}

/** Fingerprint stand-in for a nested named definition, which is tracked on its own. */
export function placeholder(node: AstNode): string | undefined {
  const nested = isNamedDefinition(node);
  return nested === undefined ? undefined : `def:${nested}`;
}
