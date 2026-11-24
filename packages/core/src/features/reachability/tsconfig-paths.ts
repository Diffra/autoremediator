/**
 * tsconfig/jsconfig path aliases: loading `compilerOptions.paths` and resolving an aliased import.
 */
import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

export interface TsconfigPathsConfig {
  baseUrl: string;
  paths: Record<string, string[]>;
}

/**
 * Loads compilerOptions.baseUrl and compilerOptions.paths from tsconfig.json or jsconfig.json
 */
export function loadTsconfigPaths(cwd: string): TsconfigPathsConfig | undefined {
  for (const configName of ["tsconfig.json", "jsconfig.json"]) {
    const fullPath = join(cwd, configName);
    if (!existsSync(fullPath)) continue;
    try {
      const raw = readFileSync(fullPath, "utf8");
      // Remove trailing commas / comments if any for robust parsing
      const cleaned = raw.replaceAll(/\/\*[\s\S]*?\*\/|\/\/.*/g, "");
      const parsed = JSON.parse(cleaned);
      const compilerOptions = parsed.compilerOptions;
      if (compilerOptions?.paths) {
        return {
          baseUrl: compilerOptions.baseUrl ? resolve(cwd, compilerOptions.baseUrl) : cwd,
          paths: compilerOptions.paths,
        };
      }
    } catch {
      // Ignore invalid config
    }
  }
  return undefined;
}

/**
 * Resolves an aliased import path according to tsconfig paths mapping
 */
export function resolveAliasedPath(
  importSource: string,
  config?: TsconfigPathsConfig,
): string | undefined {
  if (!config?.paths || isAbsolute(importSource) || importSource.startsWith(".")) {
    return undefined;
  }

  for (const [pattern, replacements] of Object.entries(config.paths)) {
    if (pattern === importSource && replacements[0]) {
      return resolve(config.baseUrl, replacements[0]);
    }
    if (pattern.endsWith("/*")) {
      const prefix = pattern.slice(0, -2);
      if (importSource.startsWith(prefix)) {
        const suffix = importSource.slice(prefix.length);
        const replacement = replacements[0]?.slice(0, -2) ?? "";
        return resolve(config.baseUrl, replacement + suffix);
      }
    }
  }
  return undefined;
}
