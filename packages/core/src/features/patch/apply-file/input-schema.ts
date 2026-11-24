/**
 * Input schema for the apply-patch-file tool: what a caller may pass and the defaults applied
 * when parsing.
 */
import { z } from "zod";

export const applyPatchFileInputSchema = z
  .object({
    packageName: z.string().min(1).describe("The npm package name"),
    vulnerableVersion: z.string().describe("The vulnerable version string"),
    patchContent: z
      .string()
      .min(10)
      .optional()
      .describe("Unified diff patch content from generate-patch"),
    cveId: z.string().optional().describe("Optional CVE ID associated with this patch artifact"),
    confidence: z
      .number()
      .min(0)
      .max(1)
      .optional()
      .describe("Optional patch confidence score from generate-patch"),
    riskLevel: z
      .enum(["low", "medium", "high"])
      .optional()
      .describe("Optional risk level from generate-patch"),
    patches: z
      .array(
        z.object({
          filePath: z.string().min(1),
          unifiedDiff: z.string().min(10),
        }),
      )
      .optional()
      .describe("Patch list from generate-patch; first patch is applied"),
    patchesDir: z
      .string()
      .optional()
      .default("./patches")
      .describe("Directory to store patch files"),
    cwd: z.string().describe("Project root directory (for package.json)"),
    packageManager: z
      .enum(["npm", "pnpm", "yarn", "bun", "deno"])
      .optional()
      .describe("Package manager used by the target project (auto-detected if omitted)"),
    policy: z.string().optional().describe("Optional path to .autoremediator policy file"),
    installMode: z.enum(["standard", "prefer-offline", "deterministic"]).optional(),
    installPreferOffline: z.boolean().optional(),
    enforceFrozenLockfile: z.boolean().optional(),
    workspace: z.string().optional(),
    validateWithTests: z
      .boolean()
      .optional()
      .default(true)
      .describe("Run package manager test command to validate patch doesn't break anything"),
    reproductionTest: z
      .string()
      .optional()
      .describe("Optional synthesized reproduction test script verifying fix"),
    proofOfFix: z
      .union([z.boolean(), z.string()])
      .optional()
      .describe(
        "If true or script path/content, enforce dual-stage exploit reproduction (assert failure pre-patch, assert pass post-patch)",
      ),
    requireProofOfFix: z
      .boolean()
      .optional()
      .describe("If true, fail and roll back patch if proof-of-fix verification fails"),
    dryRun: z
      .boolean()
      .optional()
      .default(false)
      .describe("If true, report but do not mutate files"),
  })
  .refine((value) => Boolean(value.patchContent || (value.patches && value.patches.length > 0)), {
    message: "Either patchContent or patches must be provided",
  });

export type ApplyPatchFileInput = z.output<typeof applyPatchFileInputSchema>;
