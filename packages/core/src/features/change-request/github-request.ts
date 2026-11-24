/** Opening a GitHub pull request: REST API when a token is available, the `gh` CLI otherwise. */
import { errorMessage } from "../../shared/errors.js";
import { safeExeca } from "../../shared/exec/safe-exec.js";
import { trimChar } from "../../shared/trim.js";
import { detectRepoFromRemote } from "./git-repo.js";

export interface GitHubRequestParams {
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

export async function createGitHubRequest(
  params: GitHubRequestParams,
): Promise<string | undefined> {
  const token = params.token ?? process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;

  let repository = params.repository;
  if (!repository) {
    repository = await detectRepoFromRemote(params.cwd);
  }

  if (token && repository) {
    return createPullViaApi(params, token, repository);
  }
  return createPullViaCli(params);
}

async function createPullViaApi(
  params: GitHubRequestParams,
  token: string,
  repository: string,
): Promise<string | undefined> {
  const [owner, repo] = repository.split("/");
  const baseUrl =
    (params.githubApiUrl ? trimChar(params.githubApiUrl, "/", "end") : undefined) ||
    "https://api.github.com";
  const endpoint = `${baseUrl}/repos/${owner}/${repo}/pulls`;
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      accept: "application/vnd.github+json",
      "content-type": "application/json",
      "user-agent": "autoremediator",
      "x-github-api-version": "2022-11-28",
    },
    body: JSON.stringify({
      title: params.title,
      head: params.head,
      base: params.base,
      body: params.body,
      draft: Boolean(params.draft),
    }),
  });

  if (!response.ok) {
    const errText = await response.text().catch(() => "");
    if (response.status === 422 && /already exists/i.test(errText)) {
      return findOpenPullUrl({ baseUrl, owner, repo, head: params.head, token });
    }
    throw new Error(`GitHub API create pull request failed (${response.status}): ${errText}`);
  }

  const data = (await response.json()) as { html_url?: string };
  return data.html_url || undefined;
}

/** A re-run updated the branch of an open pull request: point at that one instead of failing. */
async function findOpenPullUrl(target: {
  baseUrl: string;
  owner: string | undefined;
  repo: string | undefined;
  head: string;
  token: string;
}): Promise<string | undefined> {
  const { baseUrl, owner, repo, head, token } = target;
  const found = await fetch(
    `${baseUrl}/repos/${owner}/${repo}/pulls?state=open&head=${encodeURIComponent(`${owner}:${head}`)}`,
    {
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/vnd.github+json",
        "user-agent": "autoremediator",
        "x-github-api-version": "2022-11-28",
      },
    },
  ).catch(() => undefined);
  const pulls = found?.ok
    ? ((await found.json().catch(() => [])) as Array<{ html_url?: string }>)
    : [];
  return pulls[0]?.html_url;
}

async function createPullViaCli(params: GitHubRequestParams): Promise<string | undefined> {
  const args = [
    "pr",
    "create",
    "--head",
    params.head,
    "--base",
    params.base,
    "--title",
    params.title,
    "--body",
    params.body,
  ];
  if (params.repository) {
    args.push("--repo", params.repository);
  }
  if (params.draft) {
    args.push("--draft");
  }

  try {
    const result = await safeExeca("gh", args, {
      cwd: params.cwd,
      stdio: "pipe",
    });
    return result.stdout.trim() || undefined;
  } catch (error) {
    if (!/already exists/i.test(errorMessage(error))) throw error;
    const view = await safeExeca(
      "gh",
      ["pr", "view", params.head, "--json", "url", "--jq", ".url"],
      {
        cwd: params.cwd,
        stdio: "pipe",
      },
    ).catch(() => undefined);
    return view?.stdout.trim() || undefined;
  }
}
