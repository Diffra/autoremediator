/**
 * Attempts driven by a host agent (Claude Code, Cursor, Copilot, ...) rather than by the built-in
 * one. The host gets an isolated checkout with the upgrade applied and the verifier's findings; it
 * edits (or proposes patches), asks for verification as often as it likes, and finalizes. The same
 * verifier and the same promotion step as the built-in agent decide what reaches the project.
 *
 * The operations live in `attempt-start.ts`, `attempt-verify.ts` and `attempt-finalize.ts`.
 */
export { finalizeAttempt } from "./attempt-finalize.js";
export { startAttempt } from "./attempt-start.js";
export { abandonAttempt, proposePatch, verifyAttempt } from "./attempt-verify.js";
export {
  context,
  loadOpen,
  viewOf,
  withVerification,
  type AttemptQuery,
  type AttemptView,
  type ProposePatchOptions,
  type StartAttemptOptions,
  type VerifyAttemptOptions,
} from "./attempt-view.js";
