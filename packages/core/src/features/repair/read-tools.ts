/** The read-only tools of the repair agent: reading, listing and searching the project. */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { tool, type ToolSet } from "ai";
import { z } from "zod";

import { errorMessage } from "../../shared/errors.js";
import { type ScopeGuard, ScopeViolation } from "./scope-guard.js";

const MAX_READ_BYTES = 40_000;
const MAX_READ_LINES = 400;
const MAX_LIST_ENTRIES = 300;
const MAX_SEARCH_MATCHES = 60;
const MAX_SEARCH_FILE_BYTES = 1_000_000;
const MAX_SEARCH_PATTERN_CHARS = 200;
/** Longest stretch of one line a search pattern is run against. */
const MAX_SEARCH_LINE_CHARS = 500;

/**
 * Whether a regular expression has a quantified group that itself contains a quantifier, such as
 * `(a+)+`, `(.*)*` or `(\w+\s?)*`. These can backtrack exponentially, and a model-supplied pattern
 * runs synchronously where no timeout can interrupt it, so they are refused up front.
 */
export function hasNestedQuantifier(pattern: string): boolean {
  // One entry per open group: does it contain a quantifier anywhere inside?
  const groups: boolean[] = [];
  const mark = () => {
    if (groups.length > 0) groups[groups.length - 1] = true;
  };
  const quantifierAt = (index: number): boolean => {
    const char = pattern[index];
    if (char === "*" || char === "+") return true;
    return char === "{" && /^\{\d+(?:,\d*)?\}/.test(pattern.slice(index, index + 24));
  };
  let index = 0;
  while (index < pattern.length) {
    const char = pattern[index];
    if (char === "\\") {
      index += 2;
    } else if (char === "[") {
      index++;
      while (index < pattern.length && pattern[index] !== "]") {
        index += pattern[index] === "\\" ? 2 : 1;
      }
      index++;
    } else if (char === "(") {
      groups.push(false);
      index++;
    } else if (char === ")") {
      const inner = groups.pop() ?? false;
      if (quantifierAt(index + 1)) {
        if (inner) return true;
        mark();
      } else if (inner) {
        mark();
      }
      index++;
    } else {
      if (quantifierAt(index)) mark();
      index++;
    }
  }
  return false;
}
const SKIPPED_DIRS = new Set([
  "node_modules",
  ".git",
  ".autoremediator",
  "dist",
  "build",
  "coverage",
  ".next",
]);
const PACKAGE_NAME = /^(@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;
const DOC_FILES = [
  "CHANGELOG.md",
  "HISTORY.md",
  "CHANGES.md",
  "MIGRATION.md",
  "UPGRADING.md",
  "README.md",
];
const MAX_DOC_BYTES = 12_000;

export const refuse = (error: unknown): string => {
  if (error instanceof ScopeViolation) return `Refused: ${error.message}`;
  return `Error: ${errorMessage(error)}`;
};

function* walk(dir: string): Generator<string> {
  let entries: string[];
  try {
    entries = readdirSync(dir).toSorted();
  } catch {
    return;
  }
  for (const entry of entries) {
    if (SKIPPED_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    let stats;
    try {
      stats = statSync(full);
    } catch {
      continue;
    }
    if (stats.isDirectory()) yield* walk(full);
    else if (stats.isFile()) yield full;
  }
}

/** The tools that only read: each is confined by the guard. */
function readFileTool(guard: ScopeGuard) {
  return tool({
    description:
      "Read a text file in the project (line-numbered). Use startLine/endLine for large files. Credentials and git internals are not readable.",
    inputSchema: z.object({
      path: z.string().describe("Path relative to the project root"),
      startLine: z.number().int().positive().optional(),
      endLine: z.number().int().positive().optional(),
    }),
    execute: async ({ path, startLine, endLine }) => {
      try {
        const full = guard.assertReadable(path);
        if (!existsSync(full) || !statSync(full).isFile()) {
          return `Error: "${path}" is not a file`;
        }
        const lines = readFileSync(full, "utf8").split("\n");
        const from = Math.max(1, startLine ?? 1);
        const to = Math.min(
          lines.length,
          endLine ?? from + MAX_READ_LINES - 1,
          from + MAX_READ_LINES - 1,
        );
        let text = lines
          .slice(from - 1, to)
          .map((line, index) => `${from + index}\t${line}`)
          .join("\n");
        if (text.length > MAX_READ_BYTES) text = `${text.slice(0, MAX_READ_BYTES)}\n[truncated]`;
        return `${path} (lines ${from}-${to} of ${lines.length})\n${text}`;
      } catch (error) {
        return refuse(error);
      }
    },
  });
}

function listFilesTool(guard: ScopeGuard) {
  return tool({
    description:
      "List the files under a directory, recursively, skipping node_modules, .git and build output.",
    inputSchema: z.object({
      dir: z
        .string()
        .optional()
        .describe("Directory relative to the project root (default: the root)"),
    }),
    execute: async ({ dir }) => {
      try {
        const full = guard.assertReadable(dir ?? ".");
        const files: string[] = [];
        for (const file of walk(full)) {
          try {
            guard.assertReadable(file);
          } catch {
            continue; // credentials are not even listed
          }
          files.push(guard.relativePath(file));
          if (files.length >= MAX_LIST_ENTRIES) break;
        }
        return files.length > 0 ? files.join("\n") : "(no files)";
      } catch (error) {
        return refuse(error);
      }
    },
  });
}

function searchCodeTool(guard: ScopeGuard) {
  return tool({
    description:
      "Search project files for a regular expression (case-sensitive). Returns file:line: text for up to 60 matches.",
    inputSchema: z.object({
      pattern: z.string().describe("JavaScript regular expression"),
      dir: z.string().optional().describe("Directory relative to the project root"),
    }),
    execute: async ({ pattern, dir }) => {
      try {
        if (pattern.length > MAX_SEARCH_PATTERN_CHARS) {
          return `Error: the pattern is too long (over ${MAX_SEARCH_PATTERN_CHARS} characters); search for a shorter literal or simpler pattern`;
        }
        if (hasNestedQuantifier(pattern)) {
          return "Error: the pattern has a nested quantifier (a repeated group that contains a repeat, like (a+)+ or (.*)*), which can hang the search; use a simpler pattern or a literal string";
        }
        let regex: RegExp;
        try {
          regex = new RegExp(pattern);
        } catch {
          return `Error: "${pattern}" is not a valid regular expression`;
        }
        const full = guard.assertReadable(dir ?? ".");
        const matches: string[] = [];
        for (const file of walk(full)) {
          try {
            guard.assertReadable(file);
            if (statSync(file).size > MAX_SEARCH_FILE_BYTES) continue;
            const text = readFileSync(file, "utf8");
            if (text.includes("\0")) continue;
            const lines = text.split("\n");
            for (const [index, line] of lines.entries()) {
              if (regex.test(line.slice(0, MAX_SEARCH_LINE_CHARS))) {
                matches.push(
                  `${guard.relativePath(file)}:${index + 1}: ${line.trim().slice(0, 200)}`,
                );
                if (matches.length >= MAX_SEARCH_MATCHES) return matches.join("\n");
              }
            }
          } catch {
            // Unreadable or off-limits files are simply not searched.
          }
        }
        return matches.length > 0 ? matches.join("\n") : "(no matches)";
      } catch (error) {
        return refuse(error);
      }
    },
  });
}

function readPackageDocsTool(guard: ScopeGuard) {
  return tool({
    description:
      "Read the upgrade notes shipped with an installed dependency (changelog, migration guide, README) and where its type definitions are. Use it to learn what changed in the new version.",
    inputSchema: z.object({ packageName: z.string() }),
    execute: async ({ packageName }) => {
      if (!PACKAGE_NAME.test(packageName)) return `Error: "${packageName}" is not a package name`;
      let root = join(guard.root, "node_modules", packageName);
      if (!existsSync(root)) return `Error: ${packageName} is not installed`;
      try {
        // A linked dependency can point anywhere; its docs are only read from inside the checkout.
        root = guard.resolveInside(root);
      } catch (error) {
        return refuse(error);
      }
      const out: string[] = [];
      try {
        const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as Record<
          string,
          unknown
        >;
        const declared = [manifest["types"], manifest["typings"]].find(
          (value) => typeof value === "string",
        );
        out.push(
          `${packageName}@${JSON.stringify(manifest["version"])} types: ${typeof declared === "string" ? declared : "(none declared)"}`,
        );
      } catch {
        out.push(`${packageName}: package.json unreadable`);
      }
      for (const name of DOC_FILES) {
        let file = join(root, name);
        if (!existsSync(file)) continue;
        try {
          file = guard.resolveInside(file);
        } catch {
          continue;
        }
        out.push(`--- ${name} ---\n${readFileSync(file, "utf8").slice(0, MAX_DOC_BYTES)}`);
        if (name !== "README.md") break;
      }
      return out.join("\n");
    },
  });
}

/** The tools that only read: each is confined by the guard. */
export function createReadTools(guard: ScopeGuard): ToolSet {
  return {
    readFile: readFileTool(guard),
    listFiles: listFilesTool(guard),
    searchCode: searchCodeTool(guard),
    readPackageDocs: readPackageDocsTool(guard),
  };
}
