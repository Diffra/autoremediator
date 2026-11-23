/**
 * Which parts of a package the project's own source uses, with file and line.
 *
 * Follows the project's bindings: `import { a } from "pkg"`, `import x from "pkg"` then `x.b()`,
 * `const { c } = require("pkg")`, `require("pkg").d`. A use is recorded per export name.
 * What cannot be followed (the module object passed along, computed member access) is recorded as
 * opaque, so a caller can tell "does not use X" from "uses the package in ways we cannot see".
 * Class instance members cannot be resolved without types; they are matched by member name only and
 * labelled `name-match`.
 */
import { readFileSync, statSync } from "node:fs";
import { relative } from "node:path";

import { walkSourceFiles } from "../reachability/check-reachability.js";
import type { CallSite } from "./types.js";
import { scanFile } from "./usage-scan.js";

export interface UsageIndex {
  packageName: string;
  filesScanned: number;
  filesUsingPackage: number;
  /** Specifiers the project imports: `pkg`, `pkg/sub`. */
  specifiers: Set<string>;
  /** specifier -> export name (`default` for the module object itself) -> sites. */
  exportUses: Map<string, Map<string, CallSite[]>>;
  /** specifier -> exported class or namespace name -> member name -> sites (static members). */
  staticMemberUses: Map<string, Map<string, Map<string, CallSite[]>>>;
  /** specifier -> sites where the module object is used in a way that cannot be followed. */
  opaque: Map<string, CallSite[]>;
  /** specifier -> every `require()` and dynamic `import()` of it. */
  requireSites: Map<string, CallSite[]>;
  /** specifier -> every static `import` / `export from` of it. */
  importSites: Map<string, CallSite[]>;
  /** `.name` accesses in files that use the package, for matching class members by name only. */
  memberNameUses: Map<string, CallSite[]>;
}

const MAX_FILES = 20_000;
const MAX_FILE_BYTES = 1024 * 1024;

export function buildUsageIndex(cwd: string, packageName: string): UsageIndex {
  const index: UsageIndex = {
    packageName,
    filesScanned: 0,
    filesUsingPackage: 0,
    specifiers: new Set(),
    exportUses: new Map(),
    staticMemberUses: new Map(),
    opaque: new Map(),
    requireSites: new Map(),
    importSites: new Map(),
    memberNameUses: new Map(),
  };

  for (const path of walkSourceFiles(cwd)) {
    if (index.filesScanned >= MAX_FILES) break;
    if (/\.d\.[cm]?ts$/.test(path)) continue;
    let code: string;
    try {
      if (statSync(path).size > MAX_FILE_BYTES) continue;
      code = readFileSync(path, "utf8");
    } catch {
      continue;
    }
    index.filesScanned++;
    if (!code.includes(packageName)) continue;
    scanFile(index, relative(cwd, path), code);
  }
  return index;
}

/** Sites using an export of a specifier; `default` and `module.exports` are the same thing. */
export function sitesForExport(
  index: UsageIndex,
  specifier: string,
  exportName: string,
): CallSite[] {
  const byName = index.exportUses.get(specifier);
  if (!byName) return [];
  const names =
    exportName === "default" || exportName === "module.exports" ? ["default"] : [exportName];
  return names.flatMap((name) => byName.get(name) ?? []);
}

export function sitesForStaticMember(
  index: UsageIndex,
  specifier: string,
  exportName: string,
  member: string,
): CallSite[] {
  return index.staticMemberUses.get(specifier)?.get(exportName)?.get(member) ?? [];
}

export function isUsed(index: UsageIndex, specifier: string): boolean {
  return index.specifiers.has(specifier);
}
