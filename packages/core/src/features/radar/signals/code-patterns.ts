/**
 * Security-relevant patterns found by walking the syntax tree of one source file: guards, limits,
 * sanitizers, validators, regular expressions and dangerous sinks. Each occurrence is keyed by the
 * normalised source text of its node so the diff can ask "was this already there?".
 */
import { parseSource, walk, type AstNode } from "../../impact/ast.js";
import { isRedosProne } from "./redos.js";
import type { RADAR_POINTS } from "./types.js";

export type CodeSignal = keyof typeof RADAR_POINTS.code;

/** One occurrence of a pattern in one file. */
export interface Finding {
  signal: CodeSignal;
  /** Normalised source text of the node: identity for "was this already there?". */
  key: string;
  line: number;
  /** Source of the line, for evidence. */
  snippet: string;
}

interface Context {
  code: string;
  starts: number[];
}

const MAX_KEY = 160;

const PROTO_NAMES = new Set(["__proto__", "constructor", "prototype"]);
const SANITIZER_NAME = /^(?:sanitiz|escape|encodeURI|purif|stripTags|stripHtml|htmlEscape)/i;
const VALIDATOR_NAME =
  /^(?:validate|isValid|assert[A-Z_]|isSafe|isPlainObject|checkPath|checkUrl|checkInput|ensure[A-Z])/;
const LIMIT_NAME =
  /^(?:MAX|LIMIT)_[A-Z_]*(?:LENGTH|SIZE|DEPTH|BYTES|LEN|COUNT)$|^MAX_?[A-Z_]*(?:LENGTH|SIZE|DEPTH|BYTES|LEN)$/;
const REJECTION_MESSAGE =
  /\binvalid\b|\billegal\b|\bforbidden\b|not allowed|\bunsafe\b|\bdisallowed\b|too (?:long|large|deep|big)|\bexceeds?\b|not permitted|\bunsupported\b.*\b(?:option|variable)\b/i;
const PATH_FUNCTION =
  /^(?:path\.)?(?:resolve|normalize|relative|isAbsolute)$|^fs\.realpath(?:Sync)?$/;
const SINK_MODULES = new Set(["child_process", "node:child_process", "vm", "node:vm"]);
const SINK_MEMBERS = new Set(["innerHTML", "outerHTML", "dangerouslySetInnerHTML"]);

/** What a node handler needs: where findings go and the string constants declared in the file. */
interface Scan {
  constants: ReadonlyMap<string, string>;
  add(signal: CodeSignal, node: AstNode, key?: string): void;
}

/** Every pattern occurrence in a source file, or undefined when it does not parse. */
export function parseFindings(file: string, code: string): Finding[] | undefined {
  const program = parseSource(file, code);
  if (!program) return undefined;
  return collectFindings(program, { code, starts: lineStarts(code) });
}

function collectFindings(program: AstNode, context: Context): Finding[] {
  const findings: Finding[] = [];
  const scan: Scan = {
    constants: stringConstants(program),
    add(signal, node, key = normalised(context, node)) {
      const line = lineOf(context.starts, node.start);
      findings.push({ signal, key, line, snippet: snippetAt(context, line) });
    },
  };
  walk(program, (node) => {
    scanNode(node, scan);
    return true;
  });
  return findings;
}

function lineStarts(code: string): number[] {
  const starts = [0];
  for (let index = 0; index < code.length; index++) {
    if (code[index] === "\n") starts.push(index + 1);
  }
  return starts;
}

function lineOf(starts: readonly number[], offset: number): number {
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if ((starts[middle] ?? 0) <= offset) low = middle;
    else high = middle - 1;
  }
  return low + 1;
}

/** The `name` of an identifier-like node, or "" when it has none. */
const nameOf = (node: AstNode | undefined): string =>
  typeof node?.name === "string" ? node.name : "";

const str = (node: unknown): string | undefined =>
  typeof (node as AstNode | undefined)?.value === "string"
    ? ((node as AstNode).value as string)
    : undefined;

function asNode(value: unknown): AstNode | undefined {
  return typeof value === "object" && value !== null && typeof (value as AstNode).type === "string"
    ? (value as AstNode)
    : undefined;
}

/** `a.b.c` as text for simple member chains, else undefined. */
function dotted(node: AstNode | undefined): string | undefined {
  if (!node) return undefined;
  if (node.type === "Identifier") return String(node.name);
  if (node.type === "ThisExpression") return "this";
  if (node.type === "MemberExpression" && node.computed !== true) {
    const object = dotted(asNode(node.object));
    const property = asNode(node.property);
    return object !== undefined && property ? `${object}.${String(property.name)}` : undefined;
  }
  return undefined;
}

function calleeName(call: AstNode): string | undefined {
  const callee = asNode(call.callee);
  if (!callee) return undefined;
  if (callee.type === "Identifier") return String(callee.name);
  if (callee.type === "MemberExpression" && callee.computed !== true) {
    return nameOf(asNode(callee.property));
  }
  return undefined;
}

function regexSource(node: AstNode): string | undefined {
  const regex = node.regex as { pattern?: string; flags?: string } | undefined;
  if (regex?.pattern !== undefined) return regex.pattern;
  return undefined;
}

function normalised(context: Context, node: AstNode): string {
  return context.code.slice(node.start, node.end).replaceAll(/\s+/g, " ").slice(0, MAX_KEY);
}

function snippetAt(context: Context, line: number): string {
  const start = context.starts[line - 1] ?? 0;
  const end = context.starts[line] ?? context.code.length;
  return context.code.slice(start, end).trim();
}

function stringArgument(call: AstNode, index: number): string | undefined {
  const args = call.arguments as unknown[] | undefined;
  return str(args?.[index]);
}

function lengthMember(node: AstNode | undefined): boolean {
  return (
    node?.type === "MemberExpression" &&
    node.computed !== true &&
    asNode(node.property)?.name === "length"
  );
}

/** `throw new Error(INVALID_VARIABLE_TEXT)`: the message is a string constant declared in the file. */
function stringConstants(program: AstNode): Map<string, string> {
  const constants = new Map<string, string>();
  walk(program, (node) => {
    if (node.type === "VariableDeclarator") {
      const id = asNode(node.id);
      const text = str(asNode(node.init));
      if (id?.type === "Identifier" && text !== undefined) constants.set(String(id.name), text);
    }
    return true;
  });
  return constants;
}

function scanNode(node: AstNode, scan: Scan): void {
  switch (node.type) {
    case "BinaryExpression": {
      scanBinary(node, scan);
      break;
    }
    case "SwitchCase": {
      const literal = str(asNode(node.test));
      if (literal !== undefined && PROTO_NAMES.has(literal) && literal !== "prototype") {
        scan.add("prototype-guard-added", node, `case ${literal}`);
      }
      break;
    }
    case "VariableDeclarator": {
      scanDeclarator(node, scan);
      break;
    }
    case "FunctionDeclaration": {
      const name = nameOf(asNode(node.id));
      if (SANITIZER_NAME.test(name)) scan.add("sanitizer-added", node, `define ${name}`);
      else if (VALIDATOR_NAME.test(name)) scan.add("validator-added", node, `define ${name}`);
      break;
    }
    case "ThrowStatement": {
      scanThrow(node, scan);
      break;
    }
    case "NewExpression":
    case "CallExpression": {
      scanCall(node, scan);
      break;
    }
    case "ImportDeclaration": {
      const source = str(asNode(node.source));
      if (source !== undefined && SINK_MODULES.has(source)) {
        scan.add("dangerous-sink-removed", node);
      }
      break;
    }
    case "Literal": {
      const source = regexSource(node);
      if (source !== undefined) scan.add(regexSignal(source), node, `regex /${source}/`);
      break;
    }
    case "AssignmentExpression": {
      scanAssignment(node, scan);
      break;
    }
    default: {
      break;
    }
  }
}

function regexSignal(source: string): CodeSignal {
  return isRedosProne(source) ? "redos-regex-replaced" : "regex-changed";
}

/** The side of a comparison that is not `.length`, or undefined when neither side is. */
function lengthComparisonOperand(
  left: AstNode | undefined,
  right: AstNode | undefined,
): AstNode | undefined {
  if (lengthMember(left)) return right;
  if (lengthMember(right)) return left;
  return undefined;
}

function scanBinary(node: AstNode, scan: Scan): void {
  const operator = String(node.operator);
  const left = asNode(node.left);
  const right = asNode(node.right);
  if (["===", "==", "!==", "!="].includes(operator)) {
    const literal = str(left) ?? str(right);
    if (literal !== undefined && PROTO_NAMES.has(literal)) {
      scan.add("prototype-guard-added", node);
    }
  }
  if ([">", ">=", "<", "<="].includes(operator)) {
    const other = lengthComparisonOperand(left, right);
    if (other) {
      const limitIdentifier = other.type === "Identifier" && LIMIT_NAME.test(String(other.name));
      const limitNumber =
        other.type === "Literal" && typeof other.value === "number" && other.value >= 64;
      if (limitIdentifier || limitNumber) scan.add("length-limit-added", node);
    }
  }
}

function scanDeclarator(node: AstNode, scan: Scan): void {
  const id = asNode(node.id);
  if (id?.type === "Identifier" && LIMIT_NAME.test(String(id.name))) {
    scan.add("length-limit-added", node, `limit ${String(id.name)}`);
  }
  if (id?.type === "Identifier" && SANITIZER_NAME.test(String(id.name))) {
    scan.add("sanitizer-added", node, `define ${String(id.name)}`);
  }
}

/** The text of an error message argument: a literal, a file constant or a template's fixed parts. */
function messageText(message: AstNode | undefined, scan: Scan): string | undefined {
  return (
    str(message) ??
    (message?.type === "Identifier" ? scan.constants.get(nameOf(message)) : undefined) ??
    templateText(message)
  );
}

function templateText(message: AstNode | undefined): string | undefined {
  if (message?.type !== "TemplateLiteral") return undefined;
  return (message.quasis as AstNode[] | undefined)
    ?.map((quasi) => (quasi.value as { cooked?: string } | undefined)?.cooked ?? "")
    .join(" ");
}

function scanThrow(node: AstNode, scan: Scan): void {
  const thrown = asNode(node.argument);
  if (thrown?.type !== "NewExpression") return;
  const message = asNode((thrown.arguments as unknown[] | undefined)?.[0]);
  const text = messageText(message, scan);
  if (text !== undefined && REJECTION_MESSAGE.test(text)) {
    scan.add("invalid-input-rejected", node, `throw ${text.slice(0, 100)}`);
  }
}

function scanAssignment(node: AstNode, scan: Scan): void {
  const target = asNode(node.left);
  if (
    target?.type === "MemberExpression" &&
    target.computed !== true &&
    SINK_MEMBERS.has(String(asNode(target.property)?.name))
  ) {
    scan.add("dangerous-sink-removed", node);
  }
}

function scanCall(node: AstNode, scan: Scan): void {
  const name = calleeName(node);
  const callee = asNode(node.callee);
  const chain = dotted(callee);
  if (node.type === "NewExpression" && callee?.type === "Identifier" && callee.name === "RegExp") {
    const pattern = stringArgument(node, 0);
    if (pattern !== undefined) scan.add(regexSignal(pattern), node, `regex /${pattern}/`);
  }
  if (name !== undefined) scanNamedCall(node, name, chain, scan);
  // Sinks: counted so that their disappearance can be seen.
  if (isSinkCall(node, callee, chain)) scan.add("dangerous-sink-removed", node);
  if (name === "require") {
    const module = stringArgument(node, 0);
    if (module !== undefined && SINK_MODULES.has(module)) {
      scan.add("dangerous-sink-removed", node);
    }
  }
}

function scanNamedCall(node: AstNode, name: string, chain: string | undefined, scan: Scan): void {
  if (SANITIZER_NAME.test(name)) scan.add("sanitizer-added", node, `call ${name}`);
  else if (VALIDATOR_NAME.test(name)) scan.add("validator-added", node, `call ${name}`);
  if (name === "timingSafeEqual") scan.add("timing-safe-compare-added", node, "timingSafeEqual");
  if (name === "hasOwn" || (name === "call" && chain?.endsWith("hasOwnProperty.call"))) {
    scan.add("own-property-check-added", node, `own ${chain ?? name}`);
  }
  if (name === "create" && chain === "Object.create") {
    const first = (node.arguments as AstNode[] | undefined)?.[0];
    if (first?.type === "Literal" && first.value === null) {
      scan.add("null-prototype-object-added", node);
    }
  }
  if (["includes", "indexOf", "startsWith", "endsWith"].includes(name)) {
    const needle = stringArgument(node, 0);
    if (needle?.includes("..")) scan.add("traversal-check-added", node);
    else if (name === "startsWith") scan.add("path-containment-added", node, "startsWith");
  }
  if (chain !== undefined && PATH_FUNCTION.test(chain)) {
    scan.add("path-containment-added", node, `path ${chain}`);
  }
}

function isSinkCall(
  node: AstNode,
  callee: AstNode | undefined,
  chain: string | undefined,
): boolean {
  const identifier = callee?.type === "Identifier" ? callee.name : undefined;
  return (
    (node.type === "CallExpression" && (identifier === "eval" || identifier === "Function")) ||
    (node.type === "NewExpression" && identifier === "Function") ||
    chain === "document.write" ||
    (chain?.startsWith("vm.run") ?? false)
  );
}
