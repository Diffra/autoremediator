/** Opening a merge or pull request on GitLab, Bitbucket and Azure DevOps. */
import { errorMessage } from "../../shared/errors.js";
import { safeExeca } from "../../shared/exec/safe-exec.js";
import { readOriginUrl } from "./git-repo.js";
import {
  createAzureDevOpsPullRequest,
  createBitbucketPullRequest,
  createGitLabMergeRequestViaApi,
  parseRemoteUrl,
  repositoryFromRemote,
} from "./hosts.js";
import type { ChangeRequestProvider } from "./types.js";

export interface OpenChangeRequestParams {
  provider: ChangeRequestProvider;
  cwd: string;
  repository?: string;
  head: string;
  base: string;
  title: string;
  body: string;
  draft?: boolean;
  token?: string;
  githubApiUrl?: string;
}

export async function openOtherHostRequest(
  params: OpenChangeRequestParams,
): Promise<string | undefined> {
  const { provider, token, ...rest } = params;
  if (provider === "gitlab") {
    return createGitLabRequest({
      cwd: rest.cwd,
      repository: rest.repository,
      source: rest.head,
      target: rest.base,
      title: rest.title,
      body: rest.body,
      draft: rest.draft,
      token,
    });
  }
  if (provider === "bitbucket") {
    return createBitbucketRequest({ ...rest, token: token! });
  }
  return createAzureDevOpsRequest({ ...rest, token: token! });
}

async function createGitLabRequest(params: {
  cwd: string;
  repository?: string;
  source: string;
  target: string;
  title: string;
  body: string;
  draft?: boolean;
  token?: string;
}): Promise<string | undefined> {
  const remote = parseRemoteUrl(await readOriginUrl(params.cwd));
  const repository =
    params.repository ?? (remote ? repositoryFromRemote("gitlab", remote) : undefined);
  const apiUrl =
    process.env.CI_API_V4_URL || (remote ? `${remote.scheme}://${remote.host}/api/v4` : undefined);

  // With a token and a resolvable project, use the REST API (works in any CI image, no glab needed).
  if (params.token && repository && apiUrl) {
    return createGitLabMergeRequestViaApi({
      apiUrl,
      repository,
      head: params.source,
      base: params.target,
      title: params.title,
      body: params.body,
      draft: params.draft,
      token: params.token,
    });
  }

  const args = [
    "mr",
    "create",
    "--source-branch",
    params.source,
    "--target-branch",
    params.target,
    "--title",
    params.title,
    "--description",
    params.body,
  ];
  if (params.repository) {
    args.push("-R", params.repository);
  }
  if (params.draft) {
    args.push("--draft");
  }

  try {
    const result = await safeExeca("glab", args, {
      cwd: params.cwd,
      stdio: "pipe",
    });
    return result.stdout.trim() || undefined;
  } catch (error) {
    // The branch update already refreshed the open merge request.
    if (/already exists/i.test(errorMessage(error))) return undefined;
    throw error;
  }
}

async function createBitbucketRequest(params: {
  cwd: string;
  repository?: string;
  head: string;
  base: string;
  title: string;
  body: string;
  draft?: boolean;
  token: string;
}): Promise<string | undefined> {
  const remote = parseRemoteUrl(await readOriginUrl(params.cwd));
  const repository =
    params.repository ?? (remote ? repositoryFromRemote("bitbucket", remote) : undefined);
  if (!repository) {
    throw new Error(
      "Could not determine the Bitbucket repository from remote.origin.url; set changeRequest.repository to workspace/repo.",
    );
  }
  return createBitbucketPullRequest({ ...params, repository });
}

async function createAzureDevOpsRequest(params: {
  cwd: string;
  repository?: string;
  head: string;
  base: string;
  title: string;
  body: string;
  draft?: boolean;
  token: string;
}): Promise<string | undefined> {
  const remote = parseRemoteUrl(await readOriginUrl(params.cwd));
  const repository =
    params.repository ?? (remote ? repositoryFromRemote("azure-devops", remote) : undefined);
  if (!repository) {
    throw new Error(
      "Could not determine the Azure DevOps repository from remote.origin.url; set changeRequest.repository to organization/project/repo.",
    );
  }
  // SSH remotes use ssh.dev.azure.com; the REST API lives on dev.azure.com.
  const host = remote?.host.replace(/^(?:vs-)?ssh\./, "");
  return createAzureDevOpsPullRequest({
    ...params,
    repository,
    baseUrl: remote && host ? `${remote.scheme}://${host}` : undefined,
  });
}
