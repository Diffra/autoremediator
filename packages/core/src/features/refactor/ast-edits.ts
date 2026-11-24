/**
 * Text edits and AST traversal shared by the codemods.
 *
 * oxc-parser returns an ESTree-shaped tree; nodes are walked dynamically and stay untyped here on
 * purpose. Edits are collected as source ranges and applied last-to-first so offsets stay valid.
 */

export interface TextEdit {
  start: number;
  end: number;
  replacement: string;
}

export function applyEdits(source: string, edits: TextEdit[]): string {
  if (edits.length === 0) {
    return source;
  }
  // Sort descending by start offset to avoid line/index shift skew
  const sorted = [...edits].toSorted((a, b) => b.start - a.start);
  let result = source;
  for (const edit of sorted) {
    result = result.slice(0, edit.start) + edit.replacement + result.slice(edit.end);
  }
  return result;
}

/**
 * Calls `visit` for a node and then for every descendant, parents before children. The `parent`
 * back-reference some parsers attach is not followed.
 */
export function visitNodes(node: any, visit: (node: any) => void): void {
  if (!node || typeof node !== "object") {
    return;
  }
  visit(node);
  for (const key of Object.keys(node)) {
    if (key === "parent") {
      continue;
    }
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        visitNodes(item, visit);
      }
    } else if (child && typeof child === "object") {
      visitNodes(child, visit);
    }
  }
}
