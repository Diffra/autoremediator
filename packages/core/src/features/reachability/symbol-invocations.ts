/**
 * Call-site tracing: does a file actually invoke a given symbol of an imported package?
 */
import { parseSync, type ParseResult } from "oxc-parser";

import { type AstNode, walkAst } from "./ast-walk.js";

/**
 * Traces AST call expressions to see if the vulnerable symbol is actually invoked.
 */
export function traceSymbolInvocations(
  content: string,
  filename: string,
  importedIdentifiers: Map<string, string>,
  targetSymbol?: string,
): { invoked: boolean; callCount: number } {
  if (!targetSymbol) {
    return { invoked: true, callCount: 1 };
  }

  let parseResult: ParseResult | undefined;
  try {
    parseResult = parseSync(filename, content);
  } catch {
    return { invoked: true, callCount: 1 };
  }

  if (!parseResult?.program) {
    return { invoked: true, callCount: 1 };
  }

  let callCount = 0;

  walkAst(parseResult.program as unknown as AstNode, (node) => {
    if (node.type === "CallExpression" || node.type === "NewExpression") {
      callCount += countInvocation(node, importedIdentifiers, targetSymbol);
    }
  });

  return {
    invoked: callCount > 0,
    callCount,
  };
}

/** One call or `new` expression: 1 when it invokes the target symbol, else 0. */
function countInvocation(
  node: AstNode,
  importedIdentifiers: Map<string, string>,
  targetSymbol: string,
): number {
  const callee = node.callee as AstNode | undefined;
  if (!callee) return 0;

  let count = 0;

  // 1. Direct identifier invocation: template()
  if (callee.type === "Identifier") {
    const name = (callee as { name?: string }).name;
    if (name) {
      const importedName = importedIdentifiers.get(name);
      if (importedName === targetSymbol || name === targetSymbol) {
        count++;
      }
    }
  }

  // 2. Member expression invocation: _.template() or lodash.template()
  if (callee.type === "MemberExpression") {
    const object = callee.object as { name?: string } | undefined;
    const property = callee.property as { name?: string; value?: string } | undefined;
    const propName = property?.name ?? property?.value;

    if (object?.name && propName) {
      const importedName = importedIdentifiers.get(object.name);
      if (
        (importedName === "*" ||
          importedName === "default" ||
          object.name === "lodash" ||
          object.name === "_") &&
        propName === targetSymbol
      ) {
        count++;
      }
    }
  }

  return count;
}
