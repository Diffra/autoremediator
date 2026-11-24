/** Opening the request on whichever host the change request targets. */
import { errorMessage } from "../../shared/errors.js";
import { createGitHubRequest } from "./github-request.js";
import { openOtherHostRequest } from "./other-hosts.js";
import type { OpenChangeRequestParams } from "./other-hosts.js";

export async function openChangeRequest(
  params: OpenChangeRequestParams,
): Promise<string | undefined> {
  const { provider, token, ...rest } = params;
  if (provider === "github") {
    return createGitHubRequest({ ...rest, token });
  }
  try {
    return await openOtherHostRequest(params);
  } catch (error) {
    // A re-run updates the branch of a request that is still open; that is not a failure.
    if (isExistingRequestError(errorMessage(error))) return undefined;
    throw error;
  }
}

/** Hosts answer a duplicate request differently; these are the phrases seen in their API errors. */
export function isExistingRequestError(message: string): boolean {
  return /already exists|already an open|active pull request|another open merge request/i.test(
    message,
  );
}
