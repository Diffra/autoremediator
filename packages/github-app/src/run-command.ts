/**
 * Runs one child process without a shell and collects its combined output.
 */
import { spawn } from "node:child_process";

import { childEnvironment } from "./child-env.js";

export async function runCommand(
  command: string,
  args: string[],
  cwd: string,
  extraEnv: Record<string, string> = {},
): Promise<{ output: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: childEnvironment(extraEnv),
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk: Buffer | string) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk: Buffer | string) => {
      stderr += chunk.toString();
    });

    child.once("error", (error) => {
      reject(error);
    });

    child.once("close", (code) => {
      resolve({
        output: [stdout, stderr].filter(Boolean).join("\n").trim(),
        exitCode: code ?? 0,
      });
    });
  });
}
