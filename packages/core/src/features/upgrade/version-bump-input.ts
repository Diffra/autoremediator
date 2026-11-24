/**
 * Input of the apply-version-bump tool. Kept apart from the tool so the planning and running
 * steps can share the parsed shape.
 */
import { z } from "zod";

export const versionBumpInputSchema = z.object({
  cwd: z.string().describe("Absolute path to the consumer project root"),
  packageManager: z
    .enum(["npm", "pnpm", "yarn", "bun", "deno"])
    .optional()
    .describe("Package manager used by the target project (auto-detected if omitted)"),
  packageName: z.string().describe("The npm package to upgrade"),
  fromVersion: z.string().describe("The currently installed vulnerable version"),
  toVersion: z.string().describe("The safe target version to upgrade to"),
  dryRun: z.boolean().default(false).describe("If true, report changes but do not write"),
  policy: z.string().optional().describe("Optional path to .autoremediator policy file"),
  runTests: z
    .boolean()
    .default(false)
    .describe("If true, run test validation after applying the fix"),
  typecheck: z
    .boolean()
    .default(false)
    .describe("If true, run typecheck validation after applying the fix"),
  installMode: z.enum(["standard", "prefer-offline", "deterministic"]).optional(),
  installPreferOffline: z.boolean().optional(),
  enforceFrozenLockfile: z.boolean().optional(),
  workspace: z.string().optional(),
  breakingChangeRefactor: z
    .boolean()
    .optional()
    .describe(
      "If true, attempt agentic call-site refactoring when validation fails after major upgrade",
    ),
  reproductionTest: z
    .string()
    .optional()
    .describe("Optional reproduction test script verifying fix"),
  proofOfFix: z
    .union([z.boolean(), z.string()])
    .optional()
    .describe("If true or script path/content, enforce dual-stage exploit reproduction"),
  requireProofOfFix: z
    .boolean()
    .optional()
    .describe("If true, fail and rollback version bump if proof-of-fix verification fails"),
  patchesDir: z
    .string()
    .optional()
    .default("./patches")
    .describe("Directory containing patch/reproduction artifacts"),
});

export type VersionBumpInput = z.output<typeof versionBumpInputSchema>;
