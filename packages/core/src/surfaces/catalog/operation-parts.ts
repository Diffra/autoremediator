/** Schemas and tool annotations the catalog operations share. */
import { z } from "zod";

import { stripUntrustedChangeRequestFields } from "../../features/change-request/index.js";
import {
  portfolioTargetSchema,
  remediateOptionsSchema,
} from "../../features/remediate/option-schemas.js";
import { OPTION_DESCRIPTIONS } from "../../infra/policy/schemas.js";
import { type OperationContext } from "./define-operation.js";

export const cveId = z.string("cveId is required (string)").min(1, "cveId is required (string)");
export const exactVersion = z
  .string("an exact version is required (string)")
  .regex(
    /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/,
    "must be an exact semver version such as 4.17.21",
  );
export const inputPath = z
  .string("inputPath is required (string)")
  .min(1, "inputPath is required (string)")
  .meta({ "x-path": true })
  .describe(OPTION_DESCRIPTIONS.inputPath);
export const targets = z
  .array(portfolioTargetSchema, "targets is required (array)")
  .describe("Repositories to remediate, each by CVE id, scan file or audit");

/** Options as the SDK expects them: untrusted change-request fields removed, provenance set. */
export function sdkOptions<T extends { source?: string }>(wire: T, context: OperationContext): T {
  const cleaned = stripUntrustedChangeRequestFields(wire);
  return { ...cleaned, source: cleaned.source ?? context.source };
}

const { dryRun: _dryRun, preview: _preview, ...planShape } = remediateOptionsSchema.shape;
export const planOptionShape = planShape;

export const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;
export const READ_ONLY_NETWORK = { ...READ_ONLY, openWorldHint: true } as const;
/** Changes the project (unless `dryRun`), so a host should ask before calling it. */
export const MUTATING = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
} as const;
/** Undoes a run: edits the project, but only by restoring what the run changed. */
export const ROLLBACK = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: false,
} as const;
/** Computes a preview; writes only its own evidence record. */
export const PLANNING = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;
