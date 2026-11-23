/** The shapes of the CI secrets checklist; see `ci-secrets.ts` for what they describe. */

export type CiProvider =
  | "github-actions"
  | "gitlab-ci"
  | "circleci"
  | "azure-pipelines"
  | "bitbucket-pipelines"
  | "travis"
  | "jenkins";

export interface CiFile {
  /** Relative to the project directory. */
  file: string;
  provider: CiProvider;
  /** Something in the file runs a package install, or runs registry packages (npx, dlx). */
  installs: boolean;
  /** Jobs that install (GitHub Actions only; other providers are read as one unit). */
  installJobs: string[];
  /** Secret names in reach of an install step, its job or the whole workflow. */
  secretNames: string[];
  /** Sensitive-looking environment variable names set or used there. */
  envNames: string[];
  /** Short observations a reviewer should see (OIDC, `secrets: inherit`, contexts). */
  notes: string[];
}

export interface ContainerFile {
  file: string;
  installs: boolean;
  /** `ARG`/`ENV` names that look sensitive, and ids of `--mount=type=secret`. */
  names: string[];
  secretMounts: string[];
}

export interface EnvTemplate {
  file: string;
  names: string[];
  /** The subset that looks like a credential. */
  sensitiveNames: string[];
}

export interface NpmrcFile {
  file: string;
  /** Names inside `${...}` references (typically the token variable). */
  envNames: string[];
  /** A token or password is written into the file itself (its value is never read out). */
  literalCredential: boolean;
}

export interface LifecycleScripts {
  file: string;
  /** Names of install-time scripts the project itself defines. */
  scripts: string[];
}

export interface ChecklistItem {
  id: string;
  text: string;
}

export interface SecretsChecklist {
  /** What this section is, in a sentence: it is read first. */
  disclaimer: string;
  ci: CiFile[];
  containers: ContainerFile[];
  envTemplates: EnvTemplate[];
  npmrc: NpmrcFile[];
  lifecycle: LifecycleScripts[];
  /** Every secret or credential name found, sorted, with where it was found. */
  secretNames: Array<{ name: string; files: string[]; inInstallScope: boolean }>;
  guidance: ChecklistItem[];
  notes: string[];
}

export const CHECKLIST_DISCLAIMER =
  "A checklist to review, not a finding that anything was compromised. It lists the names of secrets that the project's own CI, container and environment files put in reach of a package install, so you can decide what to rotate. Secret values were never read.";
