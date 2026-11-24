/**
 * Tool: apply-patch-file
 *
 * Writes generated patch files to disk and applies them using package-manager-aware
 * patch mechanisms (native pnpm/yarn when available, patch-package compatibility otherwise).
 * Optionally validates patches by running tests.
 */
import { defineTool } from "../../remediate/tools/tool-compat.js";
import { applyPatchFile } from "./apply-patch-file.js";
import { applyPatchFileInputSchema } from "./input-schema.js";

export const applyPatchFileTool = defineTool({
  description:
    "Write generated patch file and apply it using package-manager-native patch flow when available, falling back to patch-package when needed.",
  inputSchema: applyPatchFileInputSchema,
  execute: applyPatchFile,
});
