/**
 * Git access for the bisect: run git, read a file at a commit, and check and resolve the refs the
 * caller names. Refs are checked before they reach git so a value cannot pass as an option.
 */
import { safeExeca } from "../../shared/exec/safe-exec.js";

export async function git(
  cwd: string,
  args: string[],
): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  const result = await safeExeca("git", args, {
    cwd,
    stdio: "pipe",
    reject: false,
    stripFinalNewline: false,
  });
  return { ok: result.exitCode === 0, stdout: result.stdout, stderr: result.stderr };
}

export async function showAt(
  top: string,
  commit: string,
  path: string,
): Promise<string | undefined> {
  const result = await git(top, ["show", `${commit}:${path}`]);
  return result.ok ? result.stdout : undefined;
}

export function checkRef(name: string, value: string): void {
  if (!value.trim()) throw new Error(`${name} is required: a git ref (commit, tag or branch).`);
  if (value.startsWith("-") || hasControlCharacter(value)) {
    throw new Error(`${name} is not a valid git ref: ${JSON.stringify(value)}.`);
  }
}

export async function resolveCommit(top: string, name: string, ref: string): Promise<string> {
  const result = await git(top, ["rev-parse", "--verify", "--end-of-options", `${ref}^{commit}`]);
  if (!result.ok) {
    throw new Error(
      `${name} ref ${JSON.stringify(ref)} does not resolve to a commit in this repository.`,
    );
  }
  return result.stdout.trim();
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.codePointAt(index) ?? 0;
    if (code < 32 || code === 127) return true;
  }
  return false;
}
