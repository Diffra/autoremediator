/**
 * Reads one declaration (a function, class, interface, type alias, enum, variable or namespace)
 * from a declaration file into an `ApiSymbol`, with the members of its body as source text.
 */
import { isNode, memberKindOfMethod, nameOfNode, propertyName, type AstNode } from "./ast.js";
import type { ApiMember, ApiSymbol, Signature, SymbolKind } from "./dts-surface.js";
import type { ParamInfo } from "./types.js";

function squash(text: string): string {
  return text
    .replaceAll(/\/\*[\s\S]*?\*\//g, "")
    .replaceAll(/\s+/g, " ")
    .replaceAll(/\s*([,;])\s*/g, "$1 ")
    .trim();
}

function slice(code: string, node: AstNode | null | undefined): string | undefined {
  return node ? squash(code.slice(node.start, node.end)) : undefined;
}

function annotationText(code: string, annotation: unknown): string | undefined {
  if (!isNode(annotation)) return undefined;
  const inner = annotation.typeAnnotation;
  return isNode(inner) ? slice(code, inner) : slice(code, annotation);
}

function paramOf(code: string, raw: AstNode, index: number): ParamInfo {
  if (raw.type === "RestElement") {
    const argument = raw.argument as AstNode | undefined;
    return {
      name: argument?.type === "Identifier" ? String(argument.name) : `arg${index}`,
      optional: true,
      rest: true,
      type: annotationText(code, raw.typeAnnotation),
    };
  }
  if (raw.type === "Identifier") {
    return {
      name: String(raw.name),
      optional: raw.optional === true,
      rest: false,
      type: annotationText(code, raw.typeAnnotation),
    };
  }
  if (raw.type === "AssignmentPattern") {
    const left = raw.left as AstNode | undefined;
    return {
      name: left?.type === "Identifier" ? String(left.name) : `arg${index}`,
      optional: true,
      rest: false,
    };
  }
  return {
    name: `arg${index}`,
    optional: raw.optional === true,
    rest: false,
    type: annotationText(code, raw.typeAnnotation),
  };
}

function signatureOf(code: string, fn: AstNode): Signature {
  const params = ((fn.params as unknown[] | undefined) ?? [])
    .filter((param): param is AstNode => isNode(param))
    .filter((param) => !(param.type === "Identifier" && param.name === "this"))
    .map((param, index) => paramOf(code, param, index));
  const returns = annotationText(code, fn.returnType);
  const typeParams = slice(code, fn.typeParameters as AstNode | undefined);
  const paramText = params
    .map(
      (param) =>
        `${param.rest ? "..." : ""}${param.name}${param.optional && !param.rest ? "?" : ""}${param.type ? `: ${param.type}` : ""}`,
    )
    .join(", ");
  return {
    params,
    returns,
    typeParams,
    text: `${typeParams ?? ""}(${paramText}) => ${returns ?? "unknown"}`,
  };
}

export function addMember(symbol: ApiSymbol, member: ApiMember): void {
  const existing = symbol.members.get(member.key);
  if (existing) {
    existing.signatures.push(...member.signatures);
    existing.optional = existing.optional && member.optional;
    existing.type ??= member.type;
  } else {
    symbol.members.set(member.key, member);
  }
}

export function memberKey(name: string, isStatic: boolean): string {
  return isStatic ? `static ${name}` : name;
}

function propertyMember(code: string, raw: AstNode): ApiMember | undefined {
  const key = raw.key as AstNode | undefined;
  if (key?.type === "PrivateIdentifier") return undefined;
  const name = propertyName(key, raw.computed === true);
  if (name === undefined) return undefined;
  const isStatic = raw.static === true;
  return {
    key: memberKey(name, isStatic),
    name,
    static: isStatic,
    kind: "property",
    optional: raw.optional === true,
    readonly: raw.readonly === true,
    signatures: [],
    type: annotationText(code, raw.typeAnnotation) ?? "unknown",
  };
}

function methodMember(code: string, raw: AstNode): ApiMember | undefined {
  const key = raw.key as AstNode | undefined;
  if (key?.type === "PrivateIdentifier") return undefined;
  const name = propertyName(key, raw.computed === true);
  const value = raw.value as AstNode | undefined;
  if (name === undefined || !value) return undefined;
  const isStatic = raw.static === true;
  const kind = memberKindOfMethod(raw.kind as string);
  const accessorName =
    kind === "getter" || kind === "setter" ? `${kind === "getter" ? "get" : "set"} ${name}` : name;
  return {
    key: kind === "constructor" ? "[new]" : memberKey(accessorName, isStatic),
    name: kind === "constructor" ? "constructor" : name,
    static: isStatic,
    kind,
    optional: raw.optional === true,
    readonly: false,
    signatures: [signatureOf(code, value)],
  };
}

function methodSignatureMember(code: string, raw: AstNode): ApiMember | undefined {
  const name = propertyName(raw.key, raw.computed === true);
  if (name === undefined) return undefined;
  return {
    key: name,
    name,
    static: false,
    kind: "method",
    optional: raw.optional === true,
    readonly: false,
    signatures: [signatureOf(code, raw)],
  };
}

/** The `[call]` and `[new]` members of an interface or type literal. */
function callableMember(code: string, raw: AstNode, key: "[call]" | "[new]"): ApiMember {
  return {
    key,
    name: key,
    static: false,
    kind: key === "[call]" ? "call" : "construct",
    optional: false,
    readonly: false,
    signatures: [signatureOf(code, raw)],
  };
}

function indexMember(code: string, raw: AstNode): ApiMember {
  const keys = ((raw.parameters as AstNode[] | undefined) ?? [])
    .map((param) => annotationText(code, param.typeAnnotation) ?? "")
    .join(", ");
  return {
    key: "[index]",
    name: "[index]",
    static: raw.static === true,
    kind: "index",
    optional: false,
    readonly: raw.readonly === true,
    signatures: [],
    type: `${keys} -> ${annotationText(code, raw.typeAnnotation) ?? "unknown"}`,
  };
}

/** The member a class or interface body entry declares, if it declares a public one. */
function memberOfEntry(code: string, raw: AstNode): ApiMember | undefined {
  if ((raw.accessibility as string | null | undefined) === "private") return undefined;
  switch (raw.type) {
    case "PropertyDefinition":
    case "TSAbstractPropertyDefinition":
    case "TSPropertySignature": {
      return propertyMember(code, raw);
    }
    case "MethodDefinition":
    case "TSAbstractMethodDefinition": {
      return methodMember(code, raw);
    }
    case "TSMethodSignature": {
      return methodSignatureMember(code, raw);
    }
    case "TSCallSignatureDeclaration": {
      return callableMember(code, raw, "[call]");
    }
    case "TSConstructSignatureDeclaration": {
      return callableMember(code, raw, "[new]");
    }
    case "TSIndexSignature": {
      return indexMember(code, raw);
    }
    default: {
      return undefined;
    }
  }
}

function readMembers(code: string, symbol: ApiSymbol, body: unknown[]): void {
  for (const raw of body) {
    if (!isNode(raw)) continue;
    const member = memberOfEntry(code, raw);
    if (member) addMember(symbol, member);
  }
}

export function blankSymbol(name: string, kind: SymbolKind): ApiSymbol {
  return { name, kind, signatures: [], members: new Map() };
}

/** Declaration merging order: a function with a namespace, a class with an interface. */
const KIND_PRIORITY: SymbolKind[] = [
  "class",
  "function",
  "enum",
  "variable",
  "interface",
  "type",
  "namespace",
  "module",
  "value",
];

export function mergeInto(target: ApiSymbol, incoming: ApiSymbol): void {
  if (KIND_PRIORITY.indexOf(incoming.kind) < KIND_PRIORITY.indexOf(target.kind)) {
    target.kind = incoming.kind;
  }
  target.signatures.push(...incoming.signatures);
  for (const member of incoming.members.values()) {
    addMember(target, { ...member, signatures: [...member.signatures] });
  }
  target.type ??= incoming.type;
  target.extends ??= incoming.extends;
  if (incoming.typeRefs) target.typeRefs = [...(target.typeRefs ?? []), ...incoming.typeRefs];
  if (incoming.nested) {
    target.nested ??= new Map();
    for (const [name, symbol] of incoming.nested) {
      const known = target.nested.get(name);
      if (known) mergeInto(known, symbol);
      else target.nested.set(name, symbol);
    }
  }
}

function typeName(node: AstNode | undefined): string | undefined {
  if (node?.type === "Identifier") return String(node.name);
  if (node?.type === "TSQualifiedName") {
    const left = typeName(node.left as AstNode | undefined);
    const right = (node.right as { name?: string } | undefined)?.name;
    return left && right ? `${left}.${right}` : undefined;
  }
  return undefined;
}

/** Named types and inline object members a declared type is made of (`A & B & { c(): void }`). */
function collectTypeShape(code: string, symbol: ApiSymbol, type: AstNode): void {
  if (type.type === "TSIntersectionType") {
    for (const part of (type.types as AstNode[] | undefined) ?? []) {
      collectTypeShape(code, symbol, part);
    }
  } else if (type.type === "TSTypeReference") {
    const name = typeName(type.typeName as AstNode | undefined);
    if (name) symbol.typeRefs = [...(symbol.typeRefs ?? []), name];
  } else if (type.type === "TSTypeLiteral") {
    readMembers(code, symbol, (type.members as unknown[] | undefined) ?? []);
  }
}

/** The identifier a declaration is named by, or undefined for the forms we do not follow. */
function declaredName(declaration: AstNode): string | undefined {
  const id = declaration.id as AstNode | undefined;
  return id?.type === "Identifier" ? String(id.name) : undefined;
}

function bodyEntries(declaration: AstNode): unknown[] {
  return ((declaration.body as AstNode | undefined)?.body as unknown[] | undefined) ?? [];
}

function functionSymbol(code: string, declaration: AstNode, name: string): ApiSymbol {
  const symbol = blankSymbol(name, "function");
  symbol.signatures.push(signatureOf(code, declaration));
  return symbol;
}

function classSymbol(code: string, declaration: AstNode, name: string): ApiSymbol {
  const symbol = blankSymbol(name, "class");
  symbol.extends = slice(code, declaration.superClass as AstNode | undefined);
  readMembers(code, symbol, bodyEntries(declaration));
  return symbol;
}

function interfaceSymbol(code: string, declaration: AstNode, name: string): ApiSymbol {
  const symbol = blankSymbol(name, "interface");
  const parents = ((declaration.extends as AstNode[] | undefined) ?? [])
    .map((parent) => slice(code, parent))
    .filter(Boolean);
  if (parents.length > 0) symbol.extends = parents.join(", ");
  readMembers(code, symbol, bodyEntries(declaration));
  return symbol;
}

function typeAliasSymbol(code: string, declaration: AstNode, name: string): ApiSymbol {
  const symbol = blankSymbol(name, "type");
  const params = slice(code, declaration.typeParameters as AstNode | undefined) ?? "";
  const body = slice(code, declaration.typeAnnotation as AstNode | undefined) ?? "unknown";
  symbol.type = `${params}${body}`;
  return symbol;
}

function enumSymbol(code: string, declaration: AstNode, name: string): ApiSymbol {
  const symbol = blankSymbol(name, "enum");
  const members =
    ((declaration.body as AstNode | undefined)?.members as AstNode[] | undefined) ??
    (declaration.members as AstNode[] | undefined) ??
    [];
  for (const member of members) {
    const memberName = nameOfNode(member.id);
    if (memberName === undefined) continue;
    addMember(symbol, {
      key: memberName,
      name: memberName,
      static: false,
      kind: "property",
      optional: false,
      readonly: true,
      signatures: [],
      type: slice(code, member.initializer as AstNode | undefined) ?? "auto",
    });
  }
  return symbol;
}

function variableSymbols(code: string, declaration: AstNode): ApiSymbol[] {
  const result: ApiSymbol[] = [];
  for (const declarator of (declaration.declarations as AstNode[] | undefined) ?? []) {
    const id = declarator.id as AstNode | undefined;
    if (id?.type !== "Identifier") continue;
    const symbol = blankSymbol(String(id.name), "variable");
    symbol.type = annotationText(code, id.typeAnnotation) ?? "unknown";
    const annotation = (id.typeAnnotation as AstNode | undefined)?.typeAnnotation as
      | AstNode
      | undefined;
    if (annotation) collectTypeShape(code, symbol, annotation);
    result.push(symbol);
  }
  return result;
}

/** A namespace's own declarations, kept nested and also listed as members of the namespace. */
function namespaceSymbol(code: string, declaration: AstNode, name: string): ApiSymbol {
  const symbol = blankSymbol(name, "namespace");
  const nestedSymbols = new Map<string, ApiSymbol>();
  symbol.nested = nestedSymbols;
  const body = (declaration.body as AstNode | undefined)?.body as AstNode[] | undefined;
  for (const statement of body ?? []) {
    const inner =
      statement.type === "ExportNamedDeclaration"
        ? (statement.declaration as AstNode | undefined)
        : statement;
    if (!inner) continue;
    for (const nested of symbolFromDeclaration(code, inner)) {
      const known = nestedSymbols.get(nested.name);
      if (known) mergeInto(known, nested);
      else nestedSymbols.set(nested.name, nested);
      const isFunction = nested.kind === "function";
      addMember(symbol, {
        key: nested.name,
        name: nested.name,
        static: false,
        kind: isFunction ? "method" : "property",
        optional: false,
        readonly: false,
        signatures: nested.signatures,
        type: isFunction
          ? undefined
          : (nested.type ?? `${nested.kind} with ${nested.members.size} members`),
      });
    }
  }
  return symbol;
}

type NamedReader = (code: string, declaration: AstNode, name: string) => ApiSymbol;

const NAMED_READERS: Record<string, NamedReader> = {
  TSDeclareFunction: functionSymbol,
  FunctionDeclaration: functionSymbol,
  ClassDeclaration: classSymbol,
  TSAbstractClassDeclaration: classSymbol,
  TSInterfaceDeclaration: interfaceSymbol,
  TSTypeAliasDeclaration: typeAliasSymbol,
  TSEnumDeclaration: enumSymbol,
  TSModuleDeclaration: namespaceSymbol,
};

/** The symbols one top-level declaration introduces (none for the forms we do not follow). */
export function symbolFromDeclaration(code: string, declaration: AstNode): ApiSymbol[] {
  if (declaration.type === "VariableDeclaration") return variableSymbols(code, declaration);
  const read = Object.hasOwn(NAMED_READERS, declaration.type)
    ? NAMED_READERS[declaration.type]
    : undefined;
  const name = declaredName(declaration);
  return read && name !== undefined ? [read(code, declaration, name)] : [];
}
