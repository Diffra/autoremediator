import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

import YAML from "yaml";

import type { CiFile, CiProvider, ContainerFile, EnvTemplate, NpmrcFile } from "./ci-types.js";

/** Reads the CI, container, env template and `.npmrc` files that can reach a package install. */

const SENSITIVE =
  /(TOKEN|SECRET|KEY|PASSWORD|PASSWD|PASS\b|CREDENTIAL|AUTH|CERT|PRIVATE|SIGNING|API)/i;
const INSTALL =
  /\b(?:npm|pnpm|yarn|bun)\s+(?:ci|install|i|add|up|update|upgrade|dlx|x|create)\b|\byarn\s*(?:&&|;|$)|\b(?:npx|bunx)\b|\bcorepack\b|\bdocker\s+(?:build|buildx)\b|\bdocker\/build-push-action\b/im;
export const LIFECYCLE = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "prepublishOnly",
  "prepack",
];
const MAX_FILE_BYTES = 1024 * 1024;
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  ".turbo",
  "vendor",
]);

/** Variables every CI sets itself; they are not credentials. */
const BUILTIN =
  /^(?:PATH|HOME|USER|PWD|SHELL|CI|NODE_ENV|TERM|LANG|LC_ALL|TZ|HOSTNAME|TMPDIR|DEBIAN_FRONTEND|CI_[A-Z0-9_]*|GITHUB_[A-Z0-9_]*|RUNNER_[A-Z0-9_]*|GITLAB_[A-Z0-9_]*|CIRCLE_[A-Z0-9_]*|BITBUCKET_[A-Z0-9_]*|BUILD_[A-Z0-9_]*|SYSTEM_[A-Z0-9_]*|AGENT_[A-Z0-9_]*|TRAVIS_[A-Z0-9_]*|NODE_VERSION|NPM_CONFIG_[A-Z0-9_]*)$/;

export const sorted = (values: Iterable<string>): string[] => [...new Set(values)].toSorted();

export function readSmallText(path: string): string | undefined {
  try {
    const stat = lstatSync(path);
    // Never follow a symlink out of the project, and never slurp something huge.
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) return undefined;
    return readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
}

/** Files under `cwd` whose relative path passes `accept`, at most `depth` directories deep. Symlinks are not followed. */
export function walk(
  cwd: string,
  accept: (relativePath: string, name: string) => boolean,
  depth = 4,
): string[] {
  const found: string[] = [];
  const visit = (dir: string, level: number): void => {
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of names.toSorted()) {
      const full = join(dir, name);
      let stat;
      try {
        stat = lstatSync(full);
      } catch {
        continue;
      }
      if (stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) {
        // Hidden CI directories matter; other hidden ones and build output do not.
        if (
          level < depth &&
          !SKIP_DIRS.has(name) &&
          (!name.startsWith(".") || name === ".github" || name === ".circleci")
        ) {
          visit(full, level + 1);
        }
      } else if (stat.isFile() && accept(relative(cwd, full), name)) {
        found.push(relative(cwd, full));
      }
      if (found.length >= 400) return;
    }
  };
  visit(cwd, 0);
  return found;
}

function stringsIn(node: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 30) return out;
  if (typeof node === "string") out.push(node);
  else if (Array.isArray(node)) for (const child of node) stringsIn(child, out, depth + 1);
  else if (typeof node === "object" && node !== null) {
    for (const child of Object.values(node)) stringsIn(child, out, depth + 1);
  }
  return out;
}

function keysIn(node: unknown, key: string, out: string[] = [], depth = 0): string[] {
  if (depth > 30 || typeof node !== "object" || node === null) return out;
  if (Array.isArray(node)) {
    for (const child of node) keysIn(child, key, out, depth + 1);
    return out;
  }
  for (const [name, child] of Object.entries(node)) {
    if (name === key && typeof child === "object" && child !== null && !Array.isArray(child)) {
      out.push(...Object.keys(child));
    }
    keysIn(child, key, out, depth + 1);
  }
  return out;
}

const SECRET_REF = /secrets\.([A-Za-z_][A-Za-z0-9_-]*)|secrets\[\s*['"]([^'"]+)['"]\s*\]/g;

function secretsIn(node: unknown): string[] {
  const names: string[] = [];
  for (const text of stringsIn(node)) {
    for (const match of text.matchAll(SECRET_REF)) {
      const name = match[1] ?? match[2];
      if (name) names.push(name);
    }
  }
  return names;
}

const sensitiveEnvKeys = (node: unknown): string[] =>
  keysIn(node, "env").filter((name) => SENSITIVE.test(name));

function stepInstalls(step: unknown): boolean {
  if (typeof step !== "object" || step === null) return false;
  const record = step as Record<string, unknown>;
  const run = typeof record["run"] === "string" ? record["run"] : "";
  const uses = typeof record["uses"] === "string" ? record["uses"] : "";
  return INSTALL.test(run) || INSTALL.test(uses);
}

export function scanGithubWorkflow(file: string, text: string): CiFile {
  const result: CiFile = {
    file,
    provider: "github-actions",
    installs: false,
    installJobs: [],
    secretNames: [],
    envNames: [],
    notes: [],
  };
  let doc: unknown;
  try {
    doc = YAML.parse(text);
  } catch {
    // Not valid YAML: fall back to reading the text for names, and say so.
    result.installs = INSTALL.test(text);
    result.secretNames = sorted(secretsIn(text));
    result.notes.push(
      "The workflow is not valid YAML, so it was only scanned as text; jobs could not be told apart.",
    );
    return result;
  }
  const workflow = asRecord(doc);
  const jobs = asRecord(workflow["jobs"]);

  const workflowSecrets = secretsIn(workflow["env"]);
  const secrets = new Set<string>();
  const envNames = new Set<string>(sensitiveEnvKeys({ env: workflow["env"] }));

  for (const [jobId, raw] of Object.entries(jobs)) {
    const job = asRecord(raw);
    const steps = Array.isArray(job["steps"]) ? job["steps"] : [];
    const installSteps = steps.filter((step) => stepInstalls(step));
    const reusable = typeof job["uses"] === "string";
    if (installSteps.length === 0 && !reusable) continue;

    result.installJobs.push(jobId);
    result.installs = installSteps.length > 0 || result.installs;
    // Anything the job runs after the install can execute the installed code, so the whole job counts.
    for (const name of [
      ...workflowSecrets,
      ...secretsIn(job["env"]),
      ...secretsIn(steps),
      ...secretsIn(job["with"]),
      ...secretsIn(job["secrets"]),
    ]) {
      secrets.add(name);
    }
    for (const name of [...sensitiveEnvKeys({ env: job["env"] }), ...sensitiveEnvKeys(steps)]) {
      envNames.add(name);
    }

    result.notes.push(...jobNotes(jobId, job, workflow, steps));
  }
  // Names GitHub provides itself are worth one line, not a row each.
  if (secrets.delete("GITHUB_TOKEN")) {
    result.notes.push(
      "`secrets.GITHUB_TOKEN` (the automatic repository token) is in reach of an install job; its permissions are set by the workflow's `permissions:`.",
    );
  }
  result.secretNames = sorted(secrets);
  result.envNames = sorted(envNames);
  result.notes = sorted(result.notes);
  return result;
}

/** Providers read as one unit: variable names that look like credentials, plus contexts and credential ids. */
export function scanGenericCi(file: string, provider: CiProvider, text: string): CiFile {
  const names = new Set<string>();
  for (const match of text.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g)) {
    const name = match[1]!;
    if (!BUILTIN.test(name) && SENSITIVE.test(name)) names.add(name);
  }
  for (const match of text.matchAll(/\$\(([A-Za-z_][A-Za-z0-9_.]*)\)/g)) {
    const name = match[1]!;
    if (!BUILTIN.test(name) && SENSITIVE.test(name)) names.add(name);
  }
  const notes: string[] = [];
  for (const match of text.matchAll(
    /credentials\(\s*['"]([^'"]+)['"]\s*\)|credentialsId\s*:\s*['"]([^'"]+)['"]/g,
  )) {
    const id = match[1] ?? match[2];
    if (id) names.add(id);
  }
  const contexts = [
    ...text.matchAll(/^\s*-?\s*context\s*:\s*\[?\s*([A-Za-z0-9_.\- ,]+?)\s*\]?\s*$/gm),
  ].flatMap((match) => (match[1] ?? "").split(",").map((entry) => entry.trim()));
  for (const context of sorted(contexts.filter((entry) => entry !== ""))) {
    notes.push(
      `Uses the CircleCI context "${context}": every variable stored in that context is in reach of the job.`,
    );
  }
  if (
    provider === "gitlab-ci" ||
    provider === "azure-pipelines" ||
    provider === "bitbucket-pipelines" ||
    provider === "travis"
  ) {
    notes.push(
      "Variables are read from the file by name only; whether each one holds a secret depends on the CI project's settings, which are not in the repository.",
    );
  }
  return {
    file,
    provider,
    installs: INSTALL.test(text),
    installJobs: [],
    secretNames: sorted(names),
    envNames: [],
    notes,
  };
}

export const CI_FILES: Array<{ test: (path: string) => boolean; provider: CiProvider }> = [
  { test: (path) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(path), provider: "github-actions" },
  { test: (path) => path === ".gitlab-ci.yml", provider: "gitlab-ci" },
  { test: (path) => path === ".circleci/config.yml", provider: "circleci" },
  {
    test: (path) => path === "azure-pipelines.yml" || path === ".azure-pipelines.yml",
    provider: "azure-pipelines",
  },
  { test: (path) => path === "bitbucket-pipelines.yml", provider: "bitbucket-pipelines" },
  { test: (path) => path === ".travis.yml", provider: "travis" },
  { test: (path) => path === "Jenkinsfile", provider: "jenkins" },
];

export function scanDockerfile(file: string, text: string): ContainerFile {
  const names = new Set<string>();
  const mounts = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const directive = /^\s*(ARG|ENV)\s+([A-Za-z_][A-Za-z0-9_]*)/i.exec(line);
    // Only the name after the keyword is kept; whatever follows the `=` is a value and is dropped here.
    if (directive?.[2] && SENSITIVE.test(directive[2])) names.add(directive[2]);
    for (const match of line.matchAll(
      /(?:--mount=type=secret,[^\s]*?id=|--secret(?:\s+|=)(?:[^\s,]*,)*?id=)([A-Za-z0-9_.-]+)/g,
    )) {
      mounts.add(match[1]!);
    }
  }
  return { file, installs: INSTALL.test(text), names: sorted(names), secretMounts: sorted(mounts) };
}

export function scanEnvTemplate(file: string, text: string): EnvTemplate {
  const names = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
    if (match?.[1]) names.add(match[1]);
  }
  const all = sorted(names);
  return { file, names: all, sensitiveNames: all.filter((name) => SENSITIVE.test(name)) };
}

export function scanNpmrc(file: string, text: string): NpmrcFile {
  const envNames = new Set<string>();
  let literalCredential = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*[#;]/.test(line)) continue;
    const credential = /(_authToken|_auth|_password|:_authToken)\s*=\s*(.*)$/i.exec(line);
    if (!credential) continue;
    const refs = [...(credential[2] ?? "").matchAll(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g)].map(
      (match) => match[1]!,
    );
    for (const name of refs) envNames.add(name);
    // A value that is not a `${VAR}` reference is a credential written into the file; note that, not what it is.
    if (refs.length === 0 && (credential[2] ?? "").trim() !== "") literalCredential = true;
  }
  return { file, envNames: sorted(envNames), literalCredential };
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

/** What a job that runs an install says about secrets in reach: inherited secrets, OIDC, credential actions. */
function jobNotes(
  jobId: string,
  job: Record<string, unknown>,
  workflow: Record<string, unknown>,
  steps: unknown[],
): string[] {
  const notes: string[] = [];
  if (job["secrets"] === "inherit") {
    notes.push(
      `Job "${jobId}" calls a reusable workflow with \`secrets: inherit\`: every secret the caller can see is passed on.`,
    );
  }
  const permissions = asRecord(job["permissions"]);
  const topPermissions = asRecord(workflow["permissions"]);
  if (permissions["id-token"] === "write" || topPermissions["id-token"] === "write") {
    notes.push(
      `Job "${jobId}" can request an OIDC token: short-lived cloud credentials may have been minted in it.`,
    );
  }
  const credentialActions = stringsIn(steps).filter((value) =>
    /^(?:aws-actions\/configure-aws-credentials|google-github-actions\/auth|azure\/login|docker\/login-action|hashicorp\/vault-action)@/.test(
      value,
    ),
  );
  for (const action of sorted(credentialActions)) {
    notes.push(
      `Job "${jobId}" uses ${action.split("@")[0]}, which puts cloud or registry credentials in the job's environment.`,
    );
  }
  return notes;
}
