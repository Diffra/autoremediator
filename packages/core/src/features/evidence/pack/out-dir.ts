/**
 * Preparing the pack directory: create it, or remove exactly what an earlier pack wrote there,
 * and refuse anything that is not an unmodified autoremediator pack.
 */
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";

import { isRecord } from "../../../shared/guards.js";
import { sha256 } from "../../../shared/hash.js";
import { PACK_STATEMENT_FILES } from "./options.js";

interface ListedFile {
  path: string;
  sha256: string;
}

export function prepareOutDir(outDir: string): void {
  if (!existsSync(outDir)) {
    mkdirSync(outDir, { recursive: true });
    return;
  }
  if (!statSync(outDir).isDirectory()) {
    throw new Error(`outDir "${outDir}" exists and is not a directory.`);
  }
  const entries = readdirSync(outDir);
  if (entries.length === 0) return;
  if (!entries.includes("manifest.json")) {
    throw new Error(
      `outDir "${outDir}" is not empty and does not hold an evidence pack (no manifest.json). Choose an empty or new directory.`,
    );
  }
  clearEarlierPack(outDir);
}

/** Remove what an earlier pack wrote, so a regenerated pack never mixes old and new files. */
function clearEarlierPack(outDir: string): void {
  const listed = readListedFiles(outDir);
  assertUnchanged(outDir, listed);
  const removed = [...listed.map(({ path }) => path), ...PACK_STATEMENT_FILES, "manifest.json"];
  const directories = new Set<string>();
  for (const path of removed) {
    rmSync(join(outDir, path), { force: true });
    for (let dir = dirname(path); dir !== "." && dir !== "/"; dir = dirname(dir)) {
      directories.add(dir);
    }
  }
  // Remove only the directories the pack itself made, deepest first, and only when nothing else is in them.
  for (const dir of [...directories].toSorted((a, b) => b.length - a.length)) {
    const full = join(outDir, dir);
    if (existsSync(full) && readdirSync(full).length === 0) rmdirSync(full);
  }
}

function notAPack(outDir: string, why: string): Error {
  return new Error(
    `outDir "${outDir}" is not empty and its manifest.json is not an autoremediator evidence pack manifest (${why}). Nothing was removed. Choose an empty or new directory.`,
  );
}

/** The files the manifest lists, by relative path inside outDir, with the digest it recorded. */
function readListedFiles(outDir: string): ListedFile[] {
  let manifest: unknown;
  try {
    manifest = JSON.parse(readFileSync(join(outDir, "manifest.json"), "utf8"));
  } catch {
    throw notAPack(outDir, "it is not JSON");
  }
  if (!isRecord(manifest)) throw notAPack(outDir, "it is not an object");
  const generator = manifest["generator"];
  if (
    manifest["schemaVersion"] !== "1" ||
    !isRecord(generator) ||
    generator["name"] !== "autoremediator"
  ) {
    throw notAPack(outDir, "it was not written by autoremediator");
  }
  const entries = manifest["files"];
  if (!Array.isArray(entries)) throw notAPack(outDir, "it lists no files");

  const root = resolve(outDir);
  const listed: ListedFile[] = [];
  for (const entry of entries as unknown[]) {
    const path = isRecord(entry) ? entry["path"] : undefined;
    const digest = isRecord(entry) ? entry["sha256"] : undefined;
    if (typeof path !== "string" || typeof digest !== "string") {
      throw notAPack(outDir, "a file entry is malformed");
    }
    const target = resolve(root, path);
    if (
      path === "" ||
      isAbsolute(path) ||
      path === "manifest.json" ||
      !target.startsWith(`${root}${sep}`)
    ) {
      throw notAPack(outDir, `it lists a path outside the pack: ${JSON.stringify(path)}`);
    }
    listed.push({ path, sha256: digest });
  }
  return listed;
}

function assertUnchanged(outDir: string, listed: ListedFile[]): void {
  const changed = listed.flatMap(({ path, sha256: digest }) => {
    const full = join(outDir, path);
    return existsSync(full) && sha256(readFileSync(full, "utf8")) !== digest ? [path] : [];
  });
  if (changed.length > 0) {
    throw new Error(
      `outDir "${outDir}" holds an evidence pack whose files changed since the pack was written: ${changed.toSorted().join(", ")}. Nothing was removed. Move or restore them, or choose a new directory.`,
    );
  }
}
