/** Checking a written pack against its own manifest, and optionally against a trusted public key. */
import type { KeyObject } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

import { sha256 } from "../../../shared/hash.js";
import type { Statement } from "./attest.js";
import { decodeBase64, loadPublicKey, verifyEnvelope, type DsseEnvelope } from "./dsse.js";
import { PACK_STATEMENT_FILES } from "./options.js";

export interface EvidencePackVerification {
  /** Every listed file matches its digest, nothing is missing or extra, and, with a key, every signature verifies. */
  ok: boolean;
  /** At least one attestation in the pack is signed. */
  signed: boolean;
  /** A public key was given and every signed attestation verified against it. */
  signaturesVerified: boolean;
  problems: string[];
  notes: string[];
}

/**
 * Check a pack against its own manifest: every file's sha256, no missing or unlisted files, and the
 * pack attestation's subject. With `publicKeyPath`, also verify every DSSE signature against that
 * key. The key included in the pack is not a trust anchor (whoever tampered with the pack could
 * replace it), so it is never used for verification.
 */
export function verifyEvidencePack(
  packDir: string,
  options: { publicKeyPath?: string } = {},
): EvidencePackVerification {
  const dir = resolve(packDir);
  const problems: string[] = [];
  const notes: string[] = [];
  const manifestPath = join(dir, "manifest.json");
  if (!existsSync(manifestPath)) {
    return {
      ok: false,
      signed: false,
      signaturesVerified: false,
      problems: ["manifest.json is missing"],
      notes,
    };
  }
  const manifestText = readFileSync(manifestPath, "utf8");
  const listed = checkListedFiles(dir, manifestText, problems);
  const publicKey = options.publicKeyPath
    ? loadPublicKey(resolve(options.publicKeyPath))
    : undefined;
  const attestations = checkAttestations({
    dir,
    listed,
    manifestSha256: sha256(manifestText),
    publicKey,
    problems,
  });
  let allVerified = publicKey !== undefined && attestations.allVerified;
  if (!publicKey) {
    notes.push(
      attestations.signed
        ? "The attestations are signed, but no --public-key was given, so no signature was checked. The key inside the pack is not a trust anchor."
        : "The attestations are unsigned: the digests above show the files are unchanged since the manifest was written, not who wrote it.",
    );
  } else if (!attestations.signed) {
    problems.push("a public key was given but the attestations are not signed");
    allVerified = false;
  }

  return {
    ok: problems.length === 0,
    signed: attestations.signed,
    signaturesVerified: publicKey !== undefined && allVerified && attestations.signed,
    problems,
    notes,
  };
}

function listFiles(dir: string, prefix = ""): string[] {
  return readdirSync(dir).flatMap((name) => {
    const rel = prefix === "" ? name : `${prefix}/${name}`;
    return statSync(join(dir, name)).isDirectory() ? listFiles(join(dir, name), rel) : [rel];
  });
}

/** Digest-check every file the manifest lists, and report files on disk that it does not list. */
function checkListedFiles(dir: string, manifestText: string, problems: string[]): Set<string> {
  const manifest = JSON.parse(manifestText) as {
    files?: Array<{ path: unknown; sha256: unknown }>;
  };
  const listed = new Set<string>();
  for (const entry of manifest.files ?? []) {
    if (typeof entry.path !== "string" || entry.path.includes("..") || entry.path.startsWith("/")) {
      problems.push(`manifest lists an unsafe path: ${JSON.stringify(entry.path)}`);
      continue;
    }
    listed.add(entry.path);
    const full = join(dir, entry.path);
    if (!existsSync(full)) {
      problems.push(`missing: ${entry.path}`);
    } else if (sha256(readFileSync(full)) !== entry.sha256) {
      problems.push(`changed: ${entry.path} no longer matches its sha256 in the manifest`);
    }
  }
  for (const path of listFiles(dir)) {
    if (path === "manifest.json" || PACK_STATEMENT_FILES.includes(path) || listed.has(path)) {
      continue;
    }
    problems.push(`unlisted: ${path} is not in the manifest`);
  }
  return listed;
}

/** Read each attestation, check the pack attestation's subject and, given a key, every signature. */
function checkAttestations(input: {
  dir: string;
  listed: Set<string>;
  manifestSha256: string;
  publicKey: KeyObject | undefined;
  problems: string[];
}): { signed: boolean; allVerified: boolean } {
  const { dir, listed, manifestSha256, publicKey, problems } = input;
  let signed = false;
  let allVerified = true;
  const envelopes = [...listed, ...PACK_STATEMENT_FILES].filter((path) =>
    path.endsWith(".intoto.json"),
  );
  for (const path of envelopes) {
    const full = join(dir, path);
    if (!existsSync(full)) {
      if (PACK_STATEMENT_FILES.includes(path)) problems.push(`missing: ${path}`);
      continue;
    }
    let envelope: DsseEnvelope;
    let statement: Statement;
    try {
      envelope = JSON.parse(readFileSync(full, "utf8")) as DsseEnvelope;
      statement = JSON.parse(decodeBase64(envelope.payload).toString("utf8")) as Statement;
    } catch {
      problems.push(`unreadable attestation: ${path}`);
      continue;
    }
    if (envelope.signatures.length > 0) signed = true;
    if (
      path === PACK_STATEMENT_FILES[0] &&
      statement.subject?.[0]?.digest?.sha256 !== manifestSha256
    ) {
      problems.push(`${path} attests to a different manifest than the one in the pack`);
    }
    if (publicKey) {
      const check = verifyEnvelope(envelope, publicKey);
      if (!check.ok) {
        allVerified = false;
        problems.push(`signature: ${path}: ${check.reason}`);
      }
    }
  }
  return { signed, allVerified };
}
