/** Options, dependencies and fixed names shared by the steps that build and verify an evidence pack. */

/** Environment variable naming a PEM private key file to sign attestations with (CLI and SDK only). */
export const SIGNING_KEY_ENV = "AUTOREMEDIATOR_EVIDENCE_SIGNING_KEY";

export const EVIDENCE_PACK_DISCLAIMER =
  "Evidence assembled by autoremediator from files on this machine. It is not legal advice, not a conformity assessment and not a claim that any product complies with Regulation (EU) 2024/2847. The statements in it have not been reviewed by a person.";

/** The pack attestation and its statement; written after the manifest, so the manifest omits them. */
export const PACK_STATEMENT_FILES = [
  "attestations/pack.intoto.json",
  "attestations/pack.statement.json",
];

export interface EvidencePackOptions {
  /** Project directory (default: process.cwd()). */
  cwd?: string;
  /** Directory to write the pack into. Must be empty, absent, or hold an earlier pack. */
  outDir: string;
  /** Recorded runs to include (default: every run under `.autoremediator/runs/`). */
  runIds?: string[];
  /** Policy file whose suppressions become VEX statements (default: `.github/autoremediator.yml`). */
  policy?: string;
  /** Product name (default: `name` from package.json). */
  productName?: string;
  /** Product version (default: `version` from package.json). */
  productVersion?: string;
  /** Manufacturer name, written into the SBOM metadata, the OpenVEX author and the CRA drafts. */
  manufacturer?: string;
  /** OpenVEX document author (default: a marked, unreviewed draft). */
  author?: string;
  /** When the manufacturer became aware of exploitation, ISO 8601 with a time zone. Starts the Article 14 clocks. */
  awarenessAt?: string;
  /** Awareness per advisory id, for when it differs; overrides `awarenessAt`. */
  awarenessByCve?: Record<string, string>;
  /** When a corrective or mitigating measure became available to users, ISO 8601 with a time zone. */
  correctiveMeasureAt?: string;
  /** PEM private key file (Ed25519, ECDSA P-256 or P-384). Without one the attestations are unsigned. */
  signingKeyPath?: string;
  /** Which surface the call arrived on. The environment key is only honored for the CLI and SDK. */
  source?: "cli" | "sdk" | "mcp" | "openapi" | "unknown";
}

export interface EvidencePackDeps {
  now?: () => Date;
  env?: NodeJS.ProcessEnv;
}

/** Pretty JSON with a trailing newline, the form every JSON file in a pack is written in. */
export function jsonText(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}
