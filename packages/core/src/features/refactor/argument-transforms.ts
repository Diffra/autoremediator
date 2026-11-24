/**
 * Caller-supplied argument transforms: drop one argument of a call or swap two of them.
 */
import { parseSync } from "oxc-parser";

import { applyEdits, visitNodes, type TextEdit } from "./ast-edits.js";

export interface ArgumentTransformOptions {
  callee: string;
  dropIndex?: number;
  reorder?: [number, number];
}

/**
 * Transforms function call arguments via AST manipulation (dropping parameters, reordering arguments).
 */
export function transformCallArguments(
  content: string,
  options: ArgumentTransformOptions & { filePath?: string },
): { modified: boolean; newContent: string } {
  const parseResult = parseSync(options.filePath ?? "file.ts", content);
  if (!parseResult.program) {
    return { modified: false, newContent: content };
  }

  const edits: TextEdit[] = [];

  visitNodes(parseResult.program, (node) => {
    if (node.type !== "CallExpression") {
      return;
    }
    const calleeText = content.slice(node.callee.start, node.callee.end);
    const matchesCallee =
      calleeText === options.callee || calleeText.endsWith(`.${options.callee}`);
    if (!matchesCallee) {
      return;
    }
    const args = node.arguments || [];
    if (options.dropIndex !== undefined) {
      edits.push(...planArgumentDrop(args, options.dropIndex));
    }
    if (options.reorder) {
      edits.push(...planArgumentSwap(content, args, options.reorder));
    }
  });

  if (edits.length === 0) {
    return { modified: false, newContent: content };
  }

  return { modified: true, newContent: applyEdits(content, edits) };
}

function planArgumentDrop(args: any[], idx: number): TextEdit[] {
  if (idx < 0 || idx >= args.length) {
    return [];
  }
  if (args.length === 1) {
    return [{ start: args[0].start, end: args[0].end, replacement: "" }];
  }
  if (idx < args.length - 1) {
    // Not the last argument: remove up to the start of the next argument
    return [{ start: args[idx].start, end: args[idx + 1].start, replacement: "" }];
  }
  // Last argument: remove from the end of the previous argument up to end of this argument
  return [{ start: args[idx - 1].end, end: args[idx].end, replacement: "" }];
}

function planArgumentSwap(content: string, args: any[], reorder: [number, number]): TextEdit[] {
  const [i, j] = reorder;
  const inRange = i >= 0 && j >= 0 && i < args.length && j < args.length;
  if (!inRange || i === j) {
    return [];
  }
  const argIText = content.slice(args[i].start, args[i].end);
  const argJText = content.slice(args[j].start, args[j].end);
  return [
    { start: args[i].start, end: args[i].end, replacement: argJText },
    { start: args[j].start, end: args[j].end, replacement: argIText },
  ];
}
