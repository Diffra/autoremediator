/**
 * Decides whether the token may be sent where this run pushes and opens requests. The token goes
 * to the push remote (and, off GitHub, to the API host the origin names): both are checked first.
 */
import { readOriginUrl, readRemoteUrl } from "./git-repo.js";
import { checkTokenDestination } from "./hosts.js";
import type { ChangeRequestOptions, ChangeRequestProvider } from "./types.js";

export interface TokenDestination {
  pushToken: string | undefined;
  refusal: string | undefined;
}

/** Returns a function that works the answer out once, on first use, and then repeats it. */
export function createDestinationResolver(params: {
  cwd: string;
  provider: ChangeRequestProvider;
  options: ChangeRequestOptions;
  token: string | undefined;
  pushRemote: string;
}): () => Promise<TokenDestination> {
  let destination: TokenDestination | undefined;
  return async () => {
    destination ??= await resolveDestination(params);
    return destination;
  };
}

async function resolveDestination(params: {
  cwd: string;
  provider: ChangeRequestProvider;
  options: ChangeRequestOptions;
  token: string | undefined;
  pushRemote: string;
}): Promise<TokenDestination> {
  const { cwd, provider, options, token, pushRemote } = params;
  if (!token) {
    return { pushToken: undefined, refusal: undefined };
  }
  const explicitToken = Boolean(
    options.token || (options.tokenEnvVar && process.env[options.tokenEnvVar]),
  );
  const pushCheck = checkTokenDestination({
    provider,
    remoteUrl: await readRemoteUrl(cwd, pushRemote),
    explicitToken,
    githubApiUrl: options.githubApiUrl,
    forPush: true,
  });
  const apiCheck =
    provider === "github"
      ? undefined
      : checkTokenDestination({ provider, remoteUrl: await readOriginUrl(cwd), explicitToken });
  return {
    pushToken: pushCheck.send ? token : undefined,
    refusal: pushCheck.refusal ?? apiCheck?.refusal,
  };
}
