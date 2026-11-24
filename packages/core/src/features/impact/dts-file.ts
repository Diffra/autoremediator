/**
 * One declaration file read into what it declares, what it exports and what it re-exports, with
 * the members of variables resolved from the named types they are declared as.
 */
import { nameOfNode, parseSource, type AstNode } from "./ast.js";
import { mergeInto, symbolFromDeclaration } from "./dts-declarations.js";
import type { ApiSymbol } from "./dts-surface.js";

export interface DtsFileInfo {
  declared: Map<string, ApiSymbol>;
  exported: Map<string, string>;
  reexports: Array<{
    source: string;
    names?: Array<{ exported: string; imported: string }>;
    all: boolean;
    namespace?: string;
  }>;
  exportAssignment?: string;
}

export function readDtsFile(path: string, code: string): DtsFileInfo | undefined {
  const program = parseSource(path, code);
  if (!program) return undefined;
  const info: DtsFileInfo = { declared: new Map(), exported: new Map(), reexports: [] };

  const declare = (symbols: ApiSymbol[], exported: boolean): void => {
    for (const symbol of symbols) {
      const existing = info.declared.get(symbol.name);
      if (existing) mergeInto(existing, symbol);
      else info.declared.set(symbol.name, symbol);
      if (exported) info.exported.set(symbol.name, symbol.name);
    }
  };

  for (const statement of (program.body as AstNode[] | undefined) ?? []) {
    switch (statement.type) {
      case "ExportNamedDeclaration": {
        const declaration = statement.declaration as AstNode | null;
        const source = (statement.source as { value?: string } | null)?.value;
        if (declaration) {
          declare(symbolFromDeclaration(code, declaration), true);
        } else if (source) {
          info.reexports.push({
            source,
            all: false,
            names: ((statement.specifiers as AstNode[] | undefined) ?? []).map((specifier) => ({
              exported: nameOfNode(specifier.exported) ?? "",
              imported: nameOfNode(specifier.local) ?? "",
            })),
          });
        } else {
          for (const specifier of (statement.specifiers as AstNode[] | undefined) ?? []) {
            const exported = nameOfNode(specifier.exported) ?? "";
            const local = nameOfNode(specifier.local) ?? "";
            if (exported && local) info.exported.set(exported, local);
          }
        }
        break;
      }
      case "ExportAllDeclaration": {
        const source = (statement.source as { value?: string } | undefined)?.value;
        const exported = statement.exported as { name?: string; value?: string } | null;
        if (source) {
          info.reexports.push({
            source,
            all: !exported,
            namespace: exported?.name ?? exported?.value,
          });
        }
        break;
      }
      case "ExportDefaultDeclaration": {
        const declaration = statement.declaration as AstNode | undefined;
        if (!declaration) break;
        if (declaration.type === "Identifier") {
          info.exported.set("default", String(declaration.name));
        } else {
          const symbols = symbolFromDeclaration(code, declaration);
          if (symbols[0]) {
            symbols[0].name = "default";
            declare(symbols, true);
          }
        }
        break;
      }
      case "TSExportAssignment": {
        const expression = statement.expression as AstNode | undefined;
        if (expression?.type === "Identifier") info.exportAssignment = String(expression.name);
        break;
      }
      default: {
        declare(symbolFromDeclaration(code, statement), false);
        break;
      }
    }
  }
  for (const symbol of info.declared.values()) expandTypeRefs(info.declared, symbol, 0);
  return info;
}

function lookupType(declared: Map<string, ApiSymbol>, name: string): ApiSymbol | undefined {
  const [head, ...rest] = name.split(".");
  let current = head ? declared.get(head) : undefined;
  for (const part of rest) current = current?.nested?.get(part);
  return current;
}

/** Give a variable the members of the named types it is declared as (and their base interfaces). */
function expandTypeRefs(declared: Map<string, ApiSymbol>, symbol: ApiSymbol, depth: number): void {
  if (depth > 3) return;
  const refs = [...(symbol.typeRefs ?? [])];
  if (symbol.kind === "interface" && symbol.extends) {
    for (const part of symbol.extends.split(",")) {
      const name = /^[A-Za-z_$][\w$.]*/.exec(part.trim())?.[0];
      if (name) refs.push(name);
    }
  }
  for (const ref of refs) {
    const target = lookupType(declared, ref);
    if (!target || target === symbol) continue;
    expandTypeRefs(declared, target, depth + 1);
    for (const member of target.members.values()) {
      if (!symbol.members.has(member.key)) {
        symbol.members.set(member.key, { ...member, signatures: [...member.signatures] });
      }
    }
  }
  symbol.typeRefs = undefined;
}
