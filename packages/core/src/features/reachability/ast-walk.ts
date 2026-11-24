/**
 * Minimal depth-first walk over an Oxc AST, shared by the reference and invocation scans.
 */

export interface AstNode {
  type: string;
  [key: string]: unknown;
}

export function walkAst(node: AstNode | null | undefined, visitor: (node: AstNode) => void): void {
  if (!node || typeof node !== "object") return;
  visitor(node);

  for (const key of Object.keys(node)) {
    if (key === "parent" || key === "start" || key === "end") continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) {
        if (child && typeof child === "object" && "type" in child) {
          walkAst(child as AstNode, visitor);
        }
      }
    } else if (value && typeof value === "object" && "type" in value) {
      walkAst(value as AstNode, visitor);
    }
  }
}
