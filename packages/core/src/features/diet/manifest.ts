import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

import type { DependencySection } from "./types.js";

/** A `package.json` as far as the dependency analysis reads it. */
export interface Manifest {
  name?: string;
  version?: string;
  private?: boolean;
  engines?: unknown;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  peerDependenciesMeta?: Record<string, { optional?: boolean }>;
  bin?: string | Record<string, string>;
  bundledDependencies?: string[];
  bundleDependencies?: string[];
  [key: string]: unknown;
}

export const SECTIONS: readonly DependencySection[] = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
];

/** Manifest fields that describe the package rather than configure a tool. */
const STRUCTURAL_FIELDS = new Set([
  "name",
  "version",
  "description",
  "keywords",
  "homepage",
  "bugs",
  "license",
  "author",
  "contributors",
  "funding",
  "repository",
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
  "peerDependenciesMeta",
  "bundledDependencies",
  "bundleDependencies",
  "dependenciesMeta",
  "overrides",
  "resolutions",
  "pnpm",
  "scripts",
  "files",
  "publishConfig",
]);

/** The manifest fields a tool reads its configuration from (`eslintConfig`, `jest`, `babel`, ...). */
export function manifestConfigText(manifest: Manifest): string {
  const config: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(manifest)) {
    if (!STRUCTURAL_FIELDS.has(key)) config[key] = value;
  }
  return JSON.stringify(config);
}

/** `Manifest.scripts` as one text per script, labelled for evidence. */
export function scriptTexts(manifest: Manifest): [label: string, text: string][] {
  return Object.entries(manifest.scripts ?? {}).map(([name, text]) => [
    `package.json#scripts.${name}`,
    text,
  ]);
}

export function readManifest(file: string): Manifest | undefined {
  try {
    const parsed: unknown = JSON.parse(readFileSync(file, "utf8"));
    return typeof parsed === "object" && parsed !== null ? (parsed as Manifest) : undefined;
  } catch {
    return undefined;
  }
}

/** `node_modules/<name>/package.json`, looked up the way Node resolves it: here, then each parent. */
export function readInstalledManifest(
  packageDir: string,
  name: string,
  stopAt: string,
): Manifest | undefined {
  let directory = resolve(packageDir);
  const limit = resolve(stopAt);
  for (;;) {
    const file = join(directory, "node_modules", name, "package.json");
    if (existsSync(file)) return readManifest(file);
    if (directory === limit) return undefined;
    const parent = dirname(directory);
    if (parent === directory) return undefined;
    directory = parent;
  }
}

/** Command names a package installs, from its `bin` field. */
export function binNames(manifest: Manifest, packageName: string): string[] {
  const bin = manifest.bin;
  if (typeof bin === "string") return [packageName.split("/").at(-1) ?? packageName];
  return bin && typeof bin === "object" ? Object.keys(bin) : [];
}
