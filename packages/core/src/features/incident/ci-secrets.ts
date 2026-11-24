import { join } from "node:path";

import {
  CI_FILES,
  LIFECYCLE,
  readSmallText,
  scanDockerfile,
  scanEnvTemplate,
  scanGenericCi,
  scanGithubWorkflow,
  scanNpmrc,
  sorted,
  walk,
} from "./ci-scan.js";
import {
  CHECKLIST_DISCLAIMER,
  type ChecklistItem,
  type CiFile,
  type ContainerFile,
  type EnvTemplate,
  type LifecycleScripts,
  type NpmrcFile,
  type SecretsChecklist,
} from "./ci-types.js";

export {
  CHECKLIST_DISCLAIMER,
  type ChecklistItem,
  type CiFile,
  type CiProvider,
  type ContainerFile,
  type EnvTemplate,
  type LifecycleScripts,
  type NpmrcFile,
  type SecretsChecklist,
} from "./ci-types.js";

/**
 * Which secrets could have been in reach of an `npm install` that ran while a bad package version
 * was locked? This reads CI workflows, Dockerfiles, env templates, `.npmrc` and `package.json`
 * and collects the NAMES of secrets and credential variables they reference.
 *
 * It never reads a value: env templates and `.npmrc` are read line by line and only the name part
 * is kept; real `.env` files are not opened at all; a literal value written into a workflow or a
 * Dockerfile is dropped on the spot. What it returns is a checklist to review, not a finding that
 * anything was exposed.
 */

const GENERIC_GUIDANCE: ChecklistItem[] = [
  {
    id: "npm-tokens",
    text: "Rotate npm tokens that could publish or read private packages: automation and publish tokens in npmjs.com account settings, the NPM_TOKEN-style secrets named above, and any token in a developer's ~/.npmrc.",
  },
  {
    id: "ci-secrets",
    text: "Rotate the CI secrets listed above for every workflow that installs dependencies, starting with deploy keys, cloud credentials and registry tokens. Check the CI provider's audit log for use of them outside normal runs.",
  },
  {
    id: "cloud-keys",
    text: "Rotate cloud access keys and revoke long-lived sessions (AWS access keys and STS sessions, GCP service account keys, Azure service principal secrets) that a build or a developer machine could reach. Prefer short-lived OIDC credentials afterwards.",
  },
  {
    id: "git-and-ssh",
    text: "Rotate GitHub or GitLab personal access tokens, deploy keys and SSH keys that lived on affected CI runners or developer machines, and review recent pushes, releases and workflow changes for anything you did not make.",
  },
  {
    id: "developer-machines",
    text: "Anyone who ran an install on an affected commit locally had their environment in reach too: .env files, shell history and exported variables, ~/.aws, ~/.ssh, browser-stored tokens. Ask them to check and rotate.",
  },
  {
    id: "rebuild",
    text: "Delete caches and rebuild from a clean checkout once the lockfile is back on a safe version (restore the CI cache, rebuild images, republish anything built while the bad version was present).",
  },
  {
    id: "verify",
    text: "After rotating, confirm the old credentials no longer work, and keep the incident report with the dates of the exposure window for the post-mortem.",
  },
];

/** Collect the names of secrets reachable from package installs in the project at `cwd`. */
export function scanSecrets(cwd: string): SecretsChecklist {
  const notes: string[] = [];

  const ci: CiFile[] = [];
  const containers: ContainerFile[] = [];
  const envTemplates: EnvTemplate[] = [];
  const npmrc: NpmrcFile[] = [];

  const files = walk(
    cwd,
    (path, name) =>
      CI_FILES.some((candidate) => candidate.test(path.split("\\").join("/"))) ||
      /^(?:Dockerfile(?:\..+)?|.+\.Dockerfile)$/.test(name) ||
      /^(?:\.env(?:\..+)?\.(?:example|sample|template|dist)|(?:example|sample)\.env|env\.example)$/.test(
        name,
      ) ||
      path === ".npmrc",
  );

  for (const file of files) {
    const posix = file.split("\\").join("/");
    const name = posix.slice(posix.lastIndexOf("/") + 1);
    const text = readSmallText(join(cwd, file));
    if (text === undefined) {
      notes.push(`${posix} was not read (a symlink, unreadable, or larger than 1 MB).`);
      continue;
    }
    const provider = CI_FILES.find((candidate) => candidate.test(posix))?.provider;
    if (provider === "github-actions") ci.push(scanGithubWorkflow(posix, text));
    else if (provider) ci.push(scanGenericCi(posix, provider, text));
    else if (/Dockerfile/.test(name)) containers.push(scanDockerfile(posix, text));
    else if (posix === ".npmrc") npmrc.push(scanNpmrc(posix, text));
    else envTemplates.push(scanEnvTemplate(posix, text));
  }

  const lifecycle: LifecycleScripts[] = [];
  const manifest = readSmallText(join(cwd, "package.json"));
  if (manifest !== undefined) {
    try {
      const scripts = (JSON.parse(manifest) as { scripts?: Record<string, unknown> }).scripts ?? {};
      const own = LIFECYCLE.filter((name) => typeof scripts[name] === "string");
      if (own.length > 0) lifecycle.push({ file: "package.json", scripts: own });
    } catch {
      notes.push("package.json is not valid JSON, so its install-time scripts were not listed.");
    }
  }
  if (files.length === 0 && lifecycle.length === 0) {
    notes.push(
      "No CI workflow, Dockerfile, env template or .npmrc was found, so no secret names are listed. The generic guidance still applies to developer machines.",
    );
  }
  notes.push(
    "Real .env files are never opened; only templates (.env.example and similar) are read, and only for variable names.",
  );

  const secretNames = secretNamesOf({ ci, containers, npmrc, envTemplates });

  return {
    disclaimer: CHECKLIST_DISCLAIMER,
    ci: ci.toSorted((a, b) => a.file.localeCompare(b.file)),
    containers,
    envTemplates,
    npmrc,
    lifecycle,
    secretNames,
    guidance: GENERIC_GUIDANCE,
    notes,
  };
}

/** Every secret or credential name the scanned files reference, with where and whether an install reaches it. */
function secretNamesOf(input: {
  ci: CiFile[];
  containers: ContainerFile[];
  npmrc: NpmrcFile[];
  envTemplates: EnvTemplate[];
}): SecretsChecklist["secretNames"] {
  const { ci, containers, npmrc, envTemplates } = input;
  const byName = new Map<string, { files: Set<string>; inInstallScope: boolean }>();
  const note = (name: string, file: string, install: boolean): void => {
    const entry = byName.get(name) ?? { files: new Set<string>(), inInstallScope: false };
    entry.files.add(file);
    entry.inInstallScope ||= install;
    byName.set(name, entry);
  };
  for (const entry of ci) {
    for (const name of [...entry.secretNames, ...entry.envNames]) {
      note(name, entry.file, entry.installs || entry.installJobs.length > 0);
    }
  }
  for (const entry of containers) {
    for (const name of [...entry.names, ...entry.secretMounts]) {
      note(name, entry.file, entry.installs);
    }
  }
  for (const entry of npmrc) for (const name of entry.envNames) note(name, entry.file, true);
  // Templates describe what a developer's environment holds, which a local install can reach.
  for (const entry of envTemplates) {
    for (const name of entry.sensitiveNames) note(name, entry.file, true);
  }
  return [...byName.entries()]
    .map(([name, entry]) => ({
      name,
      files: sorted(entry.files),
      inInstallScope: entry.inInstallScope,
    }))
    .toSorted((a, b) => a.name.localeCompare(b.name));
}
