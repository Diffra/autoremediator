/**
 * Tarball lookup, URL vetting, download and integrity checks for npm packages.
 *
 * A tarball URL comes from registry metadata, so it is vetted before it is fetched, and the bytes
 * are checked against the digest the registry advertises.
 */
import { createHash } from "node:crypto";

import { httpClient } from "../../../infra/http/http-client.js";
import {
  type RegistryConfig,
  defaultRegistryConfig,
  packumentUrl,
} from "../../../infra/http/registry-config.js";

const MAX_TARBALL_BYTES = 100 * 1024 * 1024;
const TARBALL_TIMEOUT_MS = 60_000;

export interface TarballInfo {
  url: string;
  /** Subresource-integrity string, e.g. `sha512-<base64>`. */
  integrity?: string;
  /** Legacy hex SHA-1, present on older packages without `integrity`. */
  shasum?: string;
}

/**
 * Look up where a version's tarball lives and how to verify it.
 * Returns undefined when the registry has no such package/version; throws on network failure.
 */
export async function getTarballInfo(
  packageName: string,
  version: string,
  registry: RegistryConfig = defaultRegistryConfig,
): Promise<TarballInfo | undefined> {
  const url = `${packumentUrl(registry, packageName)}/${encodeURIComponent(version)}`;
  const res = await httpClient({ url, headers: registry.headersFor(url) });

  if (res.status === 404) return undefined;
  if (!res.ok) {
    throw new Error(`npm registry error ${res.status} for "${packageName}@${version}"`);
  }

  const dist = (res.data as { dist?: { tarball?: string; integrity?: string; shasum?: string } })
    .dist;
  if (!dist?.tarball) return undefined;
  return { url: dist.tarball, integrity: dist.integrity, shasum: dist.shasum };
}

/** Check tarball bytes against the registry-advertised digest. Missing digests cannot be checked. */
export function verifyTarballIntegrity(
  bytes: Uint8Array,
  info: Pick<TarballInfo, "integrity" | "shasum">,
): { ok: true; verified: boolean } | { ok: false; reason: string } {
  if (info.integrity) {
    const entries = parseIntegrityEntries(info.integrity);
    if (entries.length > 0) {
      const matches = entries.some(
        ({ algorithm, digest }) => createHash(algorithm).update(bytes).digest("base64") === digest,
      );
      return matches ? { ok: true, verified: true } : { ok: false, reason: "integrity mismatch" };
    }
  }
  if (info.shasum) {
    const matches = createHash("sha1").update(bytes).digest("hex") === info.shasum.toLowerCase();
    return matches ? { ok: true, verified: true } : { ok: false, reason: "shasum mismatch" };
  }
  return { ok: true, verified: false };
}

/** A tarball URL comes from registry metadata, so it is checked before it is fetched: HTTPS only (HTTP for localhost). */
export function assertTarballUrlAllowed(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Refusing to download tarball: "${url.slice(0, 80)}" is not a URL`);
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && local)) {
    throw new Error(
      `Refusing to download tarball over ${parsed.protocol.replace(":", "")}: ${parsed.host}`,
    );
  }
}

/** Download a tarball, sending registry credentials only if configured for that exact URL. */
export async function downloadTarball(
  info: TarballInfo,
  registry: RegistryConfig = defaultRegistryConfig,
): Promise<Uint8Array> {
  assertTarballUrlAllowed(info.url);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TARBALL_TIMEOUT_MS);
  try {
    const res = await fetch(info.url, {
      headers: registry.headersFor(info.url),
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} downloading ${info.url}`);
    }
    const declared = Number.parseInt(res.headers.get("content-length") ?? "", 10);
    if (declared > MAX_TARBALL_BYTES) {
      throw new Error(`Tarball too large (${declared} bytes)`);
    }
    return await readCappedBody(res, info.url);
  } finally {
    clearTimeout(timer);
  }
}

/** An SRI string may list several digests; only the algorithms we trust are kept. */
function parseIntegrityEntries(integrity: string): Array<{ algorithm: string; digest: string }> {
  const entries: Array<{ algorithm: string; digest: string }> = [];
  for (const entry of integrity.split(/\s+/)) {
    const dash = entry.indexOf("-");
    if (dash <= 0) continue;
    const algorithm = entry.slice(0, dash);
    if (["sha512", "sha384", "sha256"].includes(algorithm)) {
      entries.push({ algorithm, digest: entry.slice(dash + 1) });
    }
  }
  return entries;
}

/** Read in chunks so a response without a declared length cannot fill memory before the cap. */
async function readCappedBody(res: Response, url: string): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = res.body?.getReader();
  if (!reader) throw new Error(`No body downloading ${url}`);
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_TARBALL_BYTES) {
      await reader.cancel().catch(() => {});
      throw new Error(`Tarball too large (more than ${MAX_TARBALL_BYTES} bytes)`);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
