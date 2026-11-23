/**
 * Public API surface of a package version: what it exports and with what shape.
 *
 * Read from declaration files (`.d.ts`) with oxc-parser when the package ships them, and from the
 * JavaScript export analysis otherwise (names, kinds, parameter counts and class members only; no
 * types). Signatures are kept as source text so a comparison can say what changed, not just that
 * something did.
 */
import { addMember, blankSymbol, memberKey } from "./dts-declarations.js";
import { readDtsFile, type DtsFileInfo } from "./dts-file.js";
import type { PackageIndex } from "./package-index.js";
import type { ParamInfo } from "./types.js";

export interface Signature {
  params: ParamInfo[];
  returns?: string;
  typeParams?: string;
  /** `<T>(a: string, b?: number) => R`, normalised. */
  text: string;
}

export type MemberKind =
  | "method"
  | "property"
  | "constructor"
  | "getter"
  | "setter"
  | "call"
  | "construct"
  | "index";

export interface ApiMember {
  /** Unique within the container: `name`, `static name`, `[call]`, `[new]`, `[index]`. */
  key: string;
  name: string;
  static: boolean;
  kind: MemberKind;
  optional: boolean;
  readonly: boolean;
  signatures: Signature[];
  /** Property type as source text. */
  type?: string;
}

export type SymbolKind =
  | "function"
  | "class"
  | "interface"
  | "type"
  | "enum"
  | "variable"
  | "namespace"
  | "module"
  | "value";

export interface ApiSymbol {
  name: string;
  kind: SymbolKind;
  signatures: Signature[];
  members: Map<string, ApiMember>;
  /** Type alias body, variable type or enum initialisers, as source text. */
  type?: string;
  /** `extends` clause as source text. */
  extends?: string;
  /** Types a variable is declared as, by name (`Chalk`, `ns.Options`), resolved into `members`. */
  typeRefs?: string[];
  /** Declarations nested in a namespace, by name. */
  nested?: Map<string, ApiSymbol>;
}

export interface ApiSurface {
  source: "types" | "js";
  entryFile?: string;
  symbols: Map<string, ApiSymbol>;
  notes: string[];
}

const MAX_DTS_DEPTH = 12;

/** A copy of a declared symbol under the name it is exported as. */
function exportedAs(symbol: ApiSymbol, name: string): ApiSymbol {
  return {
    ...symbol,
    name,
    signatures: [...symbol.signatures],
    members: new Map(symbol.members),
  };
}

/** `export * as ns from "./x"`: the target's exports become the members of one namespace. */
function namespaceOf(name: string, targetExports: Map<string, ApiSymbol>): ApiSymbol {
  const namespace = blankSymbol(name, "namespace");
  for (const [exportName, symbol] of targetExports) {
    addMember(namespace, {
      key: exportName,
      name: exportName,
      static: false,
      kind: symbol.kind === "function" ? "method" : "property",
      optional: false,
      readonly: false,
      signatures: symbol.signatures,
      type: symbol.type ?? symbol.kind,
    });
  }
  return namespace;
}

/** Adds what a re-export brings in from the file it points at. */
function applyReexport(
  result: Map<string, ApiSymbol>,
  reexport: DtsFileInfo["reexports"][number],
  targetExports: Map<string, ApiSymbol>,
): void {
  if (reexport.all) {
    for (const [name, symbol] of targetExports) {
      if (name !== "default" && !result.has(name)) result.set(name, symbol);
    }
  } else if (reexport.names) {
    for (const { exported, imported } of reexport.names) {
      const symbol = targetExports.get(imported);
      if (symbol) result.set(exported, { ...symbol, name: exported });
    }
  } else if (reexport.namespace) {
    result.set(reexport.namespace, namespaceOf(reexport.namespace, targetExports));
  }
}

/** The first declaration file a relative specifier can mean, if the package has one. */
function resolveDts(index: PackageIndex, from: string, specifier: string): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  const base = joinPath(from, specifier).replace(/\.(?:[cm]?js|d\.[cm]?ts)$/, "");
  return [`${base}.d.ts`, `${base}.d.mts`, `${base}.d.cts`, `${base}/index.d.ts`].find(
    (candidate) => index.hasFile(candidate),
  );
}

/** Public API of a package from its declaration files, starting at `entryFile`. */
export function extractDtsSurface(index: PackageIndex, entryFile: string): ApiSurface {
  const notes: string[] = [];
  const cache = new Map<string, DtsFileInfo | undefined>();
  const load = (path: string): DtsFileInfo | undefined => {
    if (!cache.has(path)) {
      const code = index.source.files.get(path);
      cache.set(path, code === undefined ? undefined : readDtsFile(path, code));
    }
    return cache.get(path);
  };

  const resolveFile = (path: string, depth: number, stack: Set<string>): Map<string, ApiSymbol> => {
    const result = new Map<string, ApiSymbol>();
    const info = load(path);
    if (!info || depth > MAX_DTS_DEPTH || stack.has(path)) return result;
    stack.add(path);

    for (const [exported, local] of info.exported) {
      const symbol = info.declared.get(local);
      if (symbol) result.set(exported, exportedAs(symbol, exported));
    }
    for (const reexport of info.reexports) {
      const target = resolveDts(index, path, reexport.source);
      if (!target) {
        notes.push(
          `Re-export from "${reexport.source}" in ${path} was not followed (outside the package).`,
        );
        continue;
      }
      applyReexport(result, reexport, resolveFile(target, depth + 1, stack));
    }
    const assigned = info.exportAssignment ? info.declared.get(info.exportAssignment) : undefined;
    if (assigned) {
      result.set("default", exportedAs(assigned, "default"));
      // `export = x` with a merged namespace: the namespace's declarations are the named exports.
      for (const [name, nested] of assigned.nested ?? []) result.set(name, nested);
    }
    stack.delete(path);
    return result;
  };

  return { source: "types", entryFile, symbols: resolveFile(entryFile, 0, new Set()), notes };
}

function joinPath(from: string, relative: string): string {
  const parts = from.split("/").slice(0, -1);
  for (const segment of relative.split("/")) {
    if (segment === "." || segment === "") continue;
    if (segment === "..") parts.pop();
    else parts.push(segment);
  }
  return parts.join("/");
}

/** Public API of a package from its JavaScript, when no declaration files are available. */
export function extractJsSurface(index: PackageIndex, entryFile: string): ApiSurface {
  const symbols = new Map<string, ApiSymbol>();
  for (const [rawName, binding] of index.exportsOf(entryFile)) {
    // A CommonJS `module.exports = fn` is what an ESM or interop consumer sees as the default.
    const name = rawName === "module.exports" ? "default" : rawName;
    const kind = symbolKindOfBinding(binding.kind);
    const symbol = blankSymbol(name, kind);
    if (binding.params) {
      const text = `(${binding.params.map((param) => `${param.rest ? "..." : ""}${param.name}${param.optional && !param.rest ? "?" : ""}`).join(", ")})`;
      symbol.signatures.push({ params: binding.params, text });
    }
    for (const member of binding.members ?? []) {
      addMember(symbol, {
        key: member.kind === "constructor" ? "[new]" : memberKey(member.name, member.static),
        name: member.name,
        static: member.static,
        kind: member.kind === "field" ? "property" : member.kind,
        optional: false,
        readonly: false,
        signatures: member.params
          ? [
              {
                params: member.params,
                text: `(${member.params.map((param) => param.name).join(", ")})`,
              },
            ]
          : [],
      });
    }
    symbols.set(name, symbol);
  }
  return {
    source: "js",
    entryFile,
    symbols,
    notes: ["Declared from JavaScript only: parameter and return types are not visible."],
  };
}

function symbolKindOfBinding(bindingKind: string): SymbolKind {
  if (bindingKind === "function" || bindingKind === "class" || bindingKind === "module") {
    return bindingKind;
  }
  return "value";
}
