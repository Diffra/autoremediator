/** Writing a pack to disk: the files, the manifest of their digests, and the attestation of the manifest. */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { sha256 } from "../../../shared/hash.js";
import { PACKAGE_VERSION } from "../../../shared/version.js";
import { PACK_PREDICATE_TYPE, STATEMENT_TYPE, type Statement } from "./attest.js";
import { createEnvelope, type SigningKey } from "./dsse.js";
import { EVIDENCE_PACK_DISCLAIMER, PACK_STATEMENT_FILES, jsonText } from "./options.js";
import { prepareOutDir } from "./out-dir.js";
import type { EvidencePackFile, EvidencePackResult, PackContents } from "./types.js";

/**
 * Write `contents` under `outDir`, then hash exactly what was written. `result` is the pack
 * description built before writing; the returned result adds the file list and the digests.
 */
export function writePack(input: {
  outDir: string;
  result: EvidencePackResult;
  contents: PackContents;
  key: SigningKey | undefined;
}): EvidencePackResult {
  const { outDir, result, contents, key } = input;
  prepareOutDir(outDir);
  const files = writeContentFiles(outDir, contents);

  const manifestText = manifestJson(result, files, key);
  const manifestBytes = writeText(outDir, "manifest.json", manifestText);
  const manifestSha256 = sha256(manifestText);

  const packStatement = createPackStatement(result, files.length, manifestSha256);
  const packBody = JSON.stringify(packStatement);
  writeText(outDir, PACK_STATEMENT_FILES[0]!, jsonText(createEnvelope(packBody, key)));
  writeText(outDir, PACK_STATEMENT_FILES[1]!, `${packBody}\n`);

  return {
    ...result,
    files,
    manifest: {
      path: "manifest.json",
      sha256: manifestSha256,
      bytes: manifestBytes,
      kind: "manifest",
    },
    packAttestation: { ...result.packAttestation, manifestSha256 },
  };
}

function writeText(outDir: string, path: string, content: string): number {
  const full = join(outDir, path);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content, "utf8");
  return Buffer.byteLength(content, "utf8");
}

function writeContentFiles(outDir: string, contents: PackContents): EvidencePackFile[] {
  return [...contents.entries()]
    .toSorted(([a], [b]) => a.localeCompare(b))
    .map(([path, { content, kind }]) => ({
      path,
      sha256: sha256(content),
      bytes: writeText(outDir, path, content),
      kind,
    }));
}

function manifestJson(
  result: EvidencePackResult,
  files: EvidencePackFile[],
  key: SigningKey | undefined,
): string {
  return jsonText({
    schemaVersion: "1",
    generator: { name: "autoremediator", version: PACKAGE_VERSION },
    generatedAt: result.generatedAt,
    disclaimer: EVIDENCE_PACK_DISCLAIMER,
    signed: result.signed,
    ...(key ? { signingKeyId: key.keyid, signingAlgorithm: key.algorithm } : {}),
    excludedFromManifest: PACK_STATEMENT_FILES,
    files: files.map(({ path, sha256: digest, bytes, kind }) => ({
      path,
      sha256: digest,
      bytes,
      kind,
    })),
  });
}

function createPackStatement(
  result: EvidencePackResult,
  fileCount: number,
  manifestSha256: string,
): Statement {
  return {
    _type: STATEMENT_TYPE,
    subject: [{ name: "manifest.json", digest: { sha256: manifestSha256 } }],
    predicateType: PACK_PREDICATE_TYPE,
    predicate: {
      generator: { name: "autoremediator", version: PACKAGE_VERSION },
      attestedAt: result.generatedAt,
      disclaimer: EVIDENCE_PACK_DISCLAIMER,
      files: fileCount,
      runAttestations: result.attestations.map((entry) => ({
        runId: entry.runId,
        ledgerHead: entry.ledgerHead,
      })),
    },
  };
}
