/** Reads the maintained package's own package.json: the facts `maintain` describes it with. */
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { errorMessage } from "../../../shared/errors.js";
import { isValidPackageName, npmPurl } from "../index.js";

export interface Manifest {
  name: string;
  version: string;
  private: boolean;
  author: string;
}

export function readManifest(cwd: string): Manifest {
  const path = join(cwd, "package.json");
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  } catch (error) {
    throw new Error(
      `maintain needs the package's own package.json at ${path}: ${errorMessage(error)}`,
      { cause: error },
    );
  }
  const { name, version } = raw;
  if (!isValidPackageName(name) || typeof version !== "string") {
    throw new Error(
      `${path} needs a valid "name" and a "version" for maintain to describe the package.`,
    );
  }
  const author = authorOf(raw["author"], npmPurl(name));
  return { name, version, private: raw["private"] === true, author: author.slice(0, 512) };
}

function authorOf(declared: unknown, fallback: string): string {
  if (typeof declared === "string" && declared.trim() !== "") return declared.trim();
  if (typeof declared !== "object" || declared === null) return fallback;
  const { name: authorName, email } = declared as { name?: unknown; email?: unknown };
  if (typeof authorName !== "string" || authorName.trim() === "") return fallback;
  return typeof email === "string" && email !== ""
    ? `${authorName.trim()} <${email}>`
    : authorName.trim();
}
