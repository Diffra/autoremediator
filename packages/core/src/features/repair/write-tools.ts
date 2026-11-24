/** The tools of the repair agent that change the checkout, run its checks or end the attempt. */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { tool, type ToolSet } from "ai";
import { z } from "zod";

import { redactSecrets } from "../../shared/redact.js";
import { MAX_PROPOSALS_PER_ATTEMPT, PROPOSAL_KINDS } from "../memory/propose.js";
import { runCommandCheck, tail } from "../verify/command-check.js";
import { refuse } from "./read-tools.js";
import type { RepairToolContext } from "./tools.js";

const MAX_WRITE_BYTES = 400_000;

function proposeMemoryTool(
  state: RepairToolContext["state"],
  proposeMemory: NonNullable<RepairToolContext["proposeMemory"]>,
) {
  return tool({
    description:
      "Propose a short, factual note for the repository's memory, for a person to review: how its tests run, a flaky test, a package that must stay pinned, an upgrade that cannot work, an install quirk. It is stored as a proposal and changes nothing until a person accepts it. Facts only, one line, no instructions or links. A few per attempt at most.",
    inputSchema: z.object({
      kind: z.enum(PROPOSAL_KINDS),
      text: z
        .string()
        .optional()
        .describe(
          "test-command: the command (e.g. pnpm run test:unit); flaky-test: the test; install-quirk and note: the fact",
        ),
      package: z.string().optional().describe("pinned-package and rejected-upgrade"),
      fromVersion: z.string().optional().describe("rejected-upgrade"),
      toVersion: z.string().optional().describe("rejected-upgrade"),
      reason: z
        .string()
        .optional()
        .describe("pinned-package and rejected-upgrade: why; flaky-test: an optional note"),
    }),
    execute: async (proposal) => {
      if ((state.memoryProposals ?? 0) >= MAX_PROPOSALS_PER_ATTEMPT) {
        return `Refused: at most ${MAX_PROPOSALS_PER_ATTEMPT} proposals per attempt.`;
      }
      state.memoryProposals = (state.memoryProposals ?? 0) + 1;
      return proposeMemory(proposal);
    },
  });
}

function editFileTool(context: RepairToolContext) {
  const { guard, state } = context;
  return tool({
    description:
      "Replace one exact occurrence of oldText with newText in a project source file (.js/.ts and variants). Fails if oldText is missing or appears more than once. Dependency files, CI workflows and config cannot be edited.",
    inputSchema: z.object({ path: z.string(), oldText: z.string().min(1), newText: z.string() }),
    execute: async ({ path, oldText, newText }) => {
      try {
        const full = guard.assertWritable(path);
        if (!existsSync(full)) {
          return `Error: "${path}" does not exist (use writeFile to create a file)`;
        }
        const text = readFileSync(full, "utf8");
        const first = text.indexOf(oldText);
        if (first === -1) return `Error: oldText was not found in "${path}"`;
        if (text.indexOf(oldText, first + 1) !== -1) {
          return `Error: oldText appears more than once in "${path}"; include more context`;
        }
        const next = text.slice(0, first) + newText + text.slice(first + oldText.length);
        if (next.length > MAX_WRITE_BYTES) return "Error: the file would become too large";
        writeFileSync(full, next, "utf8");
        state.filesChanged.add(guard.relativePath(full));
        return `Edited ${path}`;
      } catch (error) {
        return refuse(error);
      }
    },
  });
}

function writeFileTool(context: RepairToolContext) {
  const { guard, state } = context;
  return tool({
    description:
      "Create or overwrite a project source file (.js/.ts and variants) with the given content.",
    inputSchema: z.object({ path: z.string(), content: z.string() }),
    execute: async ({ path, content }) => {
      try {
        const full = guard.assertWritable(path);
        if (content.length > MAX_WRITE_BYTES) return "Error: the file is too large";
        mkdirSync(dirname(full), { recursive: true });
        writeFileSync(full, content, "utf8");
        state.filesChanged.add(guard.relativePath(full));
        return `Wrote ${path}`;
      } catch (error) {
        return refuse(error);
      }
    },
  });
}

function runCheckTool(context: RepairToolContext) {
  const { guard, commands, budget, state } = context;
  return tool({
    description:
      "Run the project's own type check, test suite or build, and return the end of its output. These are the only commands available. Each run counts against a limit.",
    inputSchema: z.object({ name: z.enum(["typecheck", "tests", "build"]) }),
    execute: async ({ name }) => {
      const command = commands[name];
      if (!command || command.length === 0) {
        return `No ${name} command is configured for this project.`;
      }
      if (state.commandRuns >= budget.maxCommandRuns) {
        return `Command limit reached (${budget.maxCommandRuns}). Submit, or give up.`;
      }
      state.commandRuns += 1;
      const outcome = await runCommandCheck(command, guard.root);
      return outcome.passed
        ? `${name}: passed`
        : `${name}: FAILED\n${redactSecrets(tail(outcome.output, 40).join("\n"))}`;
    },
  });
}

function submitTool(context: RepairToolContext) {
  const { state } = context;
  return tool({
    description:
      "Call when the checks pass and the project works with the new version. Summarise what you changed. An independent verifier then judges the result; it can send you back.",
    inputSchema: z.object({ summary: z.string() }),
    execute: async ({ summary }) => {
      state.submitted = summary;
      return "Submitted for verification.";
    },
  });
}

function giveUpTool(context: RepairToolContext) {
  const { state } = context;
  return tool({
    description: "Call if the project cannot reasonably be made to work with the new version.",
    inputSchema: z.object({ reason: z.string() }),
    execute: async ({ reason }) => {
      state.gaveUp = reason;
      return "Noted.";
    },
  });
}

/** The tools that edit files, run the project's own checks, propose memory and end the attempt. */
export function createWriteTools(context: RepairToolContext): ToolSet {
  const { state, proposeMemory } = context;
  return {
    ...(proposeMemory ? { proposeMemory: proposeMemoryTool(state, proposeMemory) } : {}),
    editFile: editFileTool(context),
    writeFile: writeFileTool(context),
    runCheck: runCheckTool(context),
    submit: submitTool(context),
    giveUp: giveUpTool(context),
  };
}
