/** Where an installed package sits in the project: shipped to consumers, dev-only or unused. */
import { loadProjectLocks, occurrencesIn, type ProjectLocks } from "../../incident/project.js";
import type { MaintainPackageFinding } from "./types.js";

export { loadProjectLocks, type ProjectLocks };

export function scopeOf(
  cwd: string,
  locks: ProjectLocks,
  name: string,
  version: string,
): MaintainPackageFinding["scope"] {
  if (locks.locks.length === 0) return "unknown";
  const found = occurrencesIn(cwd, locks.locks, (n, v) => n === name && v === version);
  if (found.length === 0) return "unknown";
  if (found.some((entry) => entry.scope === "production")) return "production";
  if (found.some((entry) => entry.scope === "development")) return "development";
  return "unreferenced";
}

/** Whether consumers of the package can run the finding's dependency. */
export function isShipped(entry: MaintainPackageFinding): boolean {
  return entry.scope === "production" || entry.scope === "unknown";
}
