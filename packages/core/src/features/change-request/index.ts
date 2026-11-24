/**
 * Change requests: after a remediation run, branch, commit, push and open a pull or merge request
 * on the project's git host. This file is the feature's public face; the flow is in `create.ts`.
 */
export { createChangeRequestsForReports } from "./create.js";
export { assertChangeRequestAllowed, stripUntrustedChangeRequestFields } from "./guards.js";
export { isExistingRequestError } from "./open-request.js";
export { groupReports } from "./plan.js";
