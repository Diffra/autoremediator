/** What the JavaScript export analysis reports about one module file. */
import type { DefinitionKind, LocalDef } from "./js-locals.js";
import type { ClassMemberInfo, ParamInfo } from "./types.js";

export interface ExportBinding {
  name: string;
  kind: DefinitionKind | "module";
  fingerprint: string;
  /** Name of the local definition this export is, when it is one. */
  local?: string;
  refs: Set<string>;
  tokens: Set<string>;
  nodeCount: number;
  params?: ParamInfo[];
  members?: ClassMemberInfo[];
  /** Relative module the value is `require`d from (`exports.x = require("./x")`). */
  moduleRef?: string;
}

export interface ReExport {
  /** Relative module specifier, or a package name for an external re-export. */
  source: string;
  kind: "all" | "named" | "namespace";
  names: Array<{ exported: string; imported: string }>;
  namespace?: string;
  /** `module.exports = require("./x")`: the default (whole-module) export carries over too. */
  includeDefault?: boolean;
}

export interface ModuleInfo {
  path: string;
  /** Fingerprint of the whole file. */
  fingerprint: string;
  locals: Map<string, LocalDef>;
  exports: Map<string, ExportBinding>;
  reexports: ReExport[];
  /** Relative modules this file imports or requires. */
  relativeImports: string[];
  /** How the exports were found; `namespace-assignments` is a weak heuristic. */
  discovery: "declared" | "namespace-assignments" | "none";
}
